<?php
// Active les sessions PHP pour la gestion de l'authentification
session_start();

// Configure les en-têtes CORS pour permettre les requêtes depuis n'importe quelle origine.
// C'est essentiel pour le développement, mais peut être restreint à des domaines spécifiques en production.
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header("Content-Type: application/json; charset=UTF-8");

// Gestion des requêtes OPTIONS (pré-vol des requêtes CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// --- Configuration de la base de données ---
// Remplacez ces valeurs par les informations de votre base de données MySQL
define('DB_HOST', 'localhost');
define('DB_NAME', 'hpdb'); // Le nom de votre base de données
define('DB_USER', 'root');         // Votre nom d'utilisateur MySQL
define('DB_PASS', '');             // Votre mot de passe MySQL (laissez vide si pas de mot de passe)

// Connecte à la base de données MySQL à l'aide de PDO
try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME, DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("SET NAMES utf8mb4"); // Assure l'encodage UTF-8
} catch (PDOException $e) {
    // En cas d'échec de connexion, renvoie une erreur JSON et arrête le script
    http_response_code(500);
    echo json_encode(["error" => "Database connection failed: " . $e->getMessage()]);
    exit();
}

// --- Gestion des utilisateurs par défaut (pour le développement) ---
// Crée un utilisateur 'admin' par défaut si la table des utilisateurs est vide.
// C'est utile pour les tests initiaux. À SUPPRIMER OU COMMENTER EN PRODUCTION !
try {
    $stmt = $pdo->query("SELECT COUNT(*) FROM users");
    $userCount = $stmt->fetchColumn();
    if ($userCount == 0) {
        $defaultPassword = password_hash('pass123', PASSWORD_BCRYPT); // Hache le mot de passe par défaut
        $stmt = $pdo->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
        $stmt->execute(['admin', $defaultPassword, 'admin']);
        // Vous pouvez ajouter d'autres utilisateurs par défaut ici si nécessaire
        $stmt->execute(['secretaire', password_hash('pass123', PASSWORD_BCRYPT), 'secretaire']);
        $stmt->execute(['medecin', password_hash('pass123', PASSWORD_BCRYPT), 'medecin']);
        $stmt->execute(['labo', password_hash('pass123', PASSWORD_BCRYPT), 'lab_agent']);
        // Pas de réponse JSON ici, car cela ne devrait pas affecter les requêtes normales
        // et c'est une opération de configuration au démarrage.
    }
} catch (PDOException $e) {
    // Gère l'erreur silencieusement ou log-la si vous le souhaitez
    error_log("Failed to create default admin user: " . $e->getMessage());
}


// Récupère la méthode de requête HTTP (GET, POST, PUT, DELETE)
$method = $_SERVER['REQUEST_METHOD'];
// Récupère le chemin de l'URL et le divise en segments
$requestUri = explode('/', trim($_SERVER['REQUEST_URI'], '/'));
// Le chemin de base de l'API est 'gh' (ajustez si votre API n'est pas dans un sous-dossier 'gh')
// Ex: si l'URL est http://localhost/gh/api.php/patients, $resource sera 'patients'
// $resource est la ressource principale demandée (ex: 'patients', 'medecins')
$resource = isset($requestUri[2]) ? $requestUri[2] : '';
// $id est l'identifiant de la ressource si présent (ex: pour /patients/123, $id sera '123')
$id = isset($requestUri[3]) ? $requestUri[3] : null;

// Décode les données JSON du corps de la requête (pour POST/PUT)
$input = json_decode(file_get_contents('php://input'), true);

// Fonction utilitaire pour renvoyer une réponse JSON
function sendResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    echo json_encode($data);
    exit();
}

// Fonction pour vérifier si l'utilisateur est authentifié et a le rôle requis
function isAuthenticated($requiredRoles = []) {
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['role'])) {
        sendResponse(["error" => "Unauthorized: Not logged in."], 401);
    }
    if (!empty($requiredRoles) && !in_array($_SESSION['role'], $requiredRoles)) {
        sendResponse(["error" => "Forbidden: Insufficient permissions for this action."], 403);
    }
    return true; // Return true if authenticated and authorized
}


// --- Routes d'Authentification ---
if ($resource === 'auth') {
    if ($id === 'login' && $method === 'POST') {
        if (!isset($input['username']) || !isset($input['password'])) {
            sendResponse(["error" => "Username and password are required."], 400);
        }

        $username = $input['username'];
        $password = $input['password'];

        try {
            $stmt = $pdo->prepare("SELECT user_id, username, password, role FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($password, $user['password'])) {
                // Authentification réussie, enregistre les informations de session
                $_SESSION['user_id'] = $user['user_id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'];
                sendResponse([
                    "message" => "Login successful!",
                    "user" => [
                        "user_id" => $user['user_id'],
                        "username" => $user['username'],
                        "role" => $user['role']
                    ]
                ]);
            } else {
                sendResponse(["error" => "Invalid username or password."], 401);
            }
        } catch (PDOException $e) {
            sendResponse(["error" => "Database error during login: " . $e->getMessage()], 500);
        }
    } elseif ($id === 'logout' && $method === 'POST') {
        // Détruit toutes les variables de session
        $_SESSION = array();
        // Supprime le cookie de session
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        // Détruit la session
        session_destroy();
        sendResponse(["message" => "Logout successful!"]);
    } elseif ($id === 'status' && $method === 'POST') {
        // Vérifie le statut de la session
        if (isset($_SESSION['user_id']) && isset($_SESSION['role'])) {
            sendResponse([
                "loggedIn" => true,
                "user" => [
                    "user_id" => $_SESSION['user_id'],
                    "username" => $_SESSION['username'],
                    "role" => $_SESSION['role']
                ]
            ]);
        } else {
            sendResponse(["loggedIn" => false]);
        }
    }
    exit(); // Arrête l'exécution après avoir géré les routes d'authentification
}

// --- Vérification de l'authentification pour toutes les autres routes ---
// Toutes les routes API ci-dessous nécessiteront une authentification
// avec des rôles spécifiques si précisé.
// Cette logique doit être placée APRÈS les routes d'authentification pour ne pas bloquer le login.
if (!isset($_SESSION['user_id'])) {
    sendResponse(["error" => "Unauthorized: Please log in."], 401);
}


// --- Routes CRUD pour les ressources ---
switch ($resource) {
    case 'users':
        isAuthenticated(['admin']); // Seuls les admins peuvent gérer les utilisateurs
        if ($method === 'GET') {
            try {
                if ($id) {
                    // Récupère un utilisateur par ID
                    $stmt = $pdo->prepare("SELECT user_id, username, role FROM users WHERE user_id = ?");
                    $stmt->execute([$id]);
                    $user = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($user) {
                        sendResponse($user);
                    } else {
                        sendResponse(["error" => "User not found."], 404);
                    }
                } else {
                    // Récupère tous les utilisateurs
                    $stmt = $pdo->query("SELECT user_id, username, role FROM users");
                    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($users);
                }
            } catch (PDOException $e) {
                sendResponse(["error" => "Database error: " . $e->getMessage()], 500);
            }
        } elseif ($method === 'POST') {
            if (!isset($input['username']) || !isset($input['password']) || !isset($input['role'])) {
                sendResponse(["error" => "Username, password and role are required."], 400);
            }
            try {
                $hashedPassword = password_hash($input['password'], PASSWORD_BCRYPT);
                $stmt = $pdo->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
                $stmt->execute([$input['username'], $hashedPassword, $input['role']]);
                sendResponse(["message" => "User created successfully!", "user_id" => $pdo->lastInsertId()], 201);
            } catch (PDOException $e) {
                if ($e->getCode() == 23000) { // Duplicate entry for unique key (username)
                    sendResponse(["error" => "Username already exists."], 409);
                } else {
                    sendResponse(["error" => "Database error: " . $e->getMessage()], 500);
                }
            }
        } elseif ($method === 'PUT') {
            if (!$id) {
                sendResponse(["error" => "User ID is required for update."], 400);
            }
            if (empty($input)) {
                sendResponse(["error" => "No data provided for update."], 400);
            }

            $updateFields = [];
            $updateValues = [];
            
            // Allow self-update of username/role, but not role change to/from admin by non-admin
            if ($id == $_SESSION['user_id'] && isset($input['role']) && $input['role'] !== $_SESSION['role'] && $_SESSION['role'] !== 'admin') {
                sendResponse(["error" => "Forbidden: You cannot change your own role unless you are an admin."], 403);
            }

            // Prevent an admin from deleting or changing their own role to non-admin
            if ($id == $_SESSION['user_id'] && isset($input['role']) && $input['role'] !== 'admin' && $_SESSION['role'] === 'admin') {
                sendResponse(["error" => "Forbidden: An admin cannot demote themselves. Ask another admin to do so."], 403);
            }


            if (isset($input['username'])) {
                $updateFields[] = "username = ?";
                $updateValues[] = $input['username'];
            }
            if (isset($input['password'])) {
                $updateFields[] = "password = ?";
                $updateValues[] = password_hash($input['password'], PASSWORD_BCRYPT);
            }
            if (isset($input['role'])) {
                $updateFields[] = "role = ?";
                $updateValues[] = $input['role'];
            }

            if (empty($updateFields)) {
                sendResponse(["error" => "No valid fields to update."], 400);
            }

            $query = "UPDATE users SET " . implode(", ", $updateFields) . " WHERE user_id = ?";
            $updateValues[] = $id;

            try {
                $stmt = $pdo->prepare($query);
                $stmt->execute($updateValues);
                if ($stmt->rowCount() > 0) {
                    sendResponse(["message" => "User updated successfully!"]);
                } else {
                    sendResponse(["error" => "User not found or no changes made."], 404);
                }
            } catch (PDOException $e) {
                 if ($e->getCode() == 23000) { // Duplicate entry for unique key (username)
                    sendResponse(["error" => "Username already exists."], 409);
                } else {
                    sendResponse(["error" => "Database error: " . $e->getMessage()], 500);
                }
            }
        } elseif ($method === 'DELETE') {
            if (!$id) {
                sendResponse(["error" => "User ID is required for deletion."], 400);
            }

            // Prevent an admin from deleting themselves
            if ($id == $_SESSION['user_id'] && $_SESSION['role'] === 'admin') {
                sendResponse(["error" => "Forbidden: An admin cannot delete their own account."], 403);
            }

            try {
                $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = ?");
                $stmt->execute([$id]);
                if ($stmt->rowCount() > 0) {
                    sendResponse(["message" => "User deleted successfully!"]);
                } else {
                    sendResponse(["error" => "User not found."], 404);
                }
            } catch (PDOException $e) {
                sendResponse(["error" => "Database error: " . $e->getMessage()], 500);
            }
        } else {
            sendResponse(["error" => "Method not allowed for /users."], 405);
        }
        break;

    case 'patients':
        // Rôles autorisés : secretaire, medecin
        isAuthenticated(['secretaire', 'medecin']);
        if ($method === 'GET') {
            try {
                $searchTerm = $_GET['search_term'] ?? '';
                if ($id) {
                    $stmt = $pdo->prepare("SELECT * FROM patients WHERE patient_id = ?");
                    $stmt->execute([$id]);
                    $patient = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($patient) { sendResponse($patient); }
                    else { sendResponse(["error" => "Patient not found."], 404); }
                } elseif (!empty($searchTerm)) {
                    $search = "%" . $searchTerm . "%";
                    $stmt = $pdo->prepare("SELECT * FROM patients WHERE nom LIKE ? OR prenom LIKE ? OR patient_id LIKE ?");
                    $stmt->execute([$search, $search, $search]);
                    $patients = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($patients);
                } else {
                    $stmt = $pdo->query("SELECT * FROM patients");
                    $patients = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($patients);
                }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'POST') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent ajouter des patients
            $required_fields = ['nom', 'prenom', 'date_naissance', 'genre', 'adresse', 'telephone'];
            foreach ($required_fields as $field) {
                if (!isset($input[$field])) { sendResponse(["error" => "Missing field: $field"], 400); }
            }
            try {
                $stmt = $pdo->prepare("INSERT INTO patients (nom, prenom, date_naissance, genre, adresse, telephone, email, allergies, antecedents_chirurgicaux, info_assurance) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([$input['nom'], $input['prenom'], $input['date_naissance'], $input['genre'], $input['adresse'], $input['telephone'], $input['email'] ?? null, $input['allergies'] ?? null, $input['antecedents_chirurgicaux'] ?? null, $input['info_assurance'] ?? null]);
                sendResponse(["message" => "Patient added successfully!", "patient_id" => $pdo->lastInsertId()], 201);
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'DELETE') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent supprimer des patients
            if (!$id) { sendResponse(["error" => "Patient ID is required."], 400); }
            try {
                $stmt = $pdo->prepare("DELETE FROM patients WHERE patient_id = ?");
                $stmt->execute([$id]);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Patient deleted successfully!"]); }
                else { sendResponse(["error" => "Patient not found."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } else { sendResponse(["error" => "Method not allowed for /patients."], 405); }
        break;

    case 'medecins':
        isAuthenticated(['secretaire', 'medecin']); // Secrétaire et médecin peuvent voir
        if ($method === 'GET') {
            try {
                if ($id) {
                    $stmt = $pdo->prepare("SELECT * FROM medecins WHERE medecin_id = ?");
                    $stmt->execute([$id]);
                    $medecin = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($medecin) { sendResponse($medecin); }
                    else { sendResponse(["error" => "Doctor not found."], 404); }
                } else {
                    $stmt = $pdo->query("SELECT * FROM medecins");
                    $medecins = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($medecins);
                }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } else { sendResponse(["error" => "Method not allowed for /medecins."], 405); }
        break;

    case 'lits':
        isAuthenticated(['secretaire', 'medecin']);
        if ($method === 'GET') {
            try {
                if ($id) {
                    $stmt = $pdo->prepare("SELECT * FROM lits WHERE lit_id = ?");
                    $stmt->execute([$id]);
                    $lit = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($lit) { sendResponse($lit); }
                    else { sendResponse(["error" => "Bed not found."], 404); }
                } else {
                    $stmt = $pdo->query("SELECT * FROM lits");
                    $lits = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($lits);
                }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'POST') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent ajouter des lits
            $required_fields = ['numero_lit', 'service', 'statut'];
            foreach ($required_fields as $field) {
                if (!isset($input[$field])) { sendResponse(["error" => "Missing field: $field"], 400); }
            }
            try {
                $stmt = $pdo->prepare("INSERT INTO lits (numero_lit, service, statut, patient_id, date_occupation) VALUES (?, ?, ?, ?, ?)");
                $stmt->execute([$input['numero_lit'], $input['service'], $input['statut'], $input['patient_id'] ?? null, $input['date_occupation'] ?? null]);
                sendResponse(["message" => "Bed added successfully!", "lit_id" => $pdo->lastInsertId()], 201);
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'PUT') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent modifier les lits
            if (!$id) { sendResponse(["error" => "Bed ID is required for update."], 400); }
            $updateFields = [];
            $updateValues = [];
            if (isset($input['numero_lit'])) { $updateFields[] = "numero_lit = ?"; $updateValues[] = $input['numero_lit']; }
            if (isset($input['service'])) { $updateFields[] = "service = ?"; $updateValues[] = $input['service']; }
            if (isset($input['statut'])) { $updateFields[] = "statut = ?"; $updateValues[] = $input['statut']; }
            // Patient_id peut être null pour libérer le lit
            if (array_key_exists('patient_id', $input)) { $updateFields[] = "patient_id = ?"; $updateValues[] = $input['patient_id']; }
            // Date_occupation peut être null pour libérer le lit
            if (array_key_exists('date_occupation', $input)) { $updateFields[] = "date_occupation = ?"; $updateValues[] = $input['date_occupation']; }

            if (empty($updateFields)) { sendResponse(["error" => "No data provided for update."], 400); }

            $query = "UPDATE lits SET " . implode(", ", $updateFields) . " WHERE lit_id = ?";
            $updateValues[] = $id;

            try {
                $stmt = $pdo->prepare($query);
                $stmt->execute($updateValues);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Bed updated successfully!"]); }
                else { sendResponse(["error" => "Bed not found or no changes made."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'DELETE') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent supprimer des lits
            if (!$id) { sendResponse(["error" => "Bed ID is required for deletion."], 400); }
            try {
                $stmt = $pdo->prepare("DELETE FROM lits WHERE lit_id = ?");
                $stmt->execute([$id]);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Bed deleted successfully!"]); }
                else { sendResponse(["error" => "Bed not found."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } else { sendResponse(["error" => "Method not allowed for /lits."], 405); }
        break;

    case 'inventaire':
        isAuthenticated(['secretaire', 'lab_agent']); // Secrétaire et agent labo
        if ($method === 'GET') {
            try {
                if ($id) {
                    $stmt = $pdo->prepare("SELECT * FROM inventaire WHERE article_id = ?");
                    $stmt->execute([$id]);
                    $item = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($item) { sendResponse($item); }
                    else { sendResponse(["error" => "Inventory item not found."], 404); }
                } else {
                    $stmt = $pdo->query("SELECT * FROM inventaire");
                    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($items);
                }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'POST') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent ajouter des items
            $required_fields = ['nom_article', 'quantite', 'seuil_alerte'];
            foreach ($required_fields as $field) {
                if (!isset($input[$field])) { sendResponse(["error" => "Missing field: $field"], 400); }
            }
            try {
                $stmt = $pdo->prepare("INSERT INTO inventaire (nom_article, quantite, unite, seuil_alerte, fournisseur) VALUES (?, ?, ?, ?, ?)");
                $stmt->execute([$input['nom_article'], $input['quantite'], $input['unite'] ?? null, $input['seuil_alerte'], $input['fournisseur'] ?? null]);
                sendResponse(["message" => "Inventory item added successfully!", "article_id" => $pdo->lastInsertId()], 201);
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'PUT') {
            isAuthenticated(['secretaire', 'lab_agent']); // Secrétaire et agent labo peuvent modifier la quantité
            if (!$id) { sendResponse(["error" => "Item ID is required for update."], 400); }
            $updateFields = [];
            $updateValues = [];
            if (isset($input['nom_article'])) { $updateFields[] = "nom_article = ?"; $updateValues[] = $input['nom_article']; }
            if (isset($input['quantite'])) { $updateFields[] = "quantite = ?"; $updateValues[] = $input['quantite']; }
            if (isset($input['unite'])) { $updateFields[] = "unite = ?"; $updateValues[] = $input['unite']; }
            if (isset($input['seuil_alerte'])) { $updateFields[] = "seuil_alerte = ?"; $updateValues[] = $input['seuil_alerte']; }
            if (isset($input['fournisseur'])) { $updateFields[] = "fournisseur = ?"; $updateValues[] = $input['fournisseur']; }

            if (empty($updateFields)) { sendResponse(["error" => "No data provided for update."], 400); }

            $query = "UPDATE inventaire SET " . implode(", ", $updateFields) . " WHERE article_id = ?";
            $updateValues[] = $id;

            try {
                $stmt = $pdo->prepare($query);
                $stmt->execute($updateValues);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Inventory item updated successfully!"]); }
                else { sendResponse(["error" => "Inventory item not found or no changes made."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'DELETE') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent supprimer des items
            if (!$id) { sendResponse(["error" => "Item ID is required for deletion."], 400); }
            try {
                $stmt = $pdo->prepare("DELETE FROM inventaire WHERE article_id = ?");
                $stmt->execute([$id]);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Inventory item deleted successfully!"]); }
                else { sendResponse(["error" => "Inventory item not found."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } else { sendResponse(["error" => "Method not allowed for /inventaire."], 405); }
        break;

    case 'diagnoses':
        isAuthenticated(['medecin']); // Seuls les médecins peuvent gérer les diagnostics
        if ($method === 'GET') {
            try {
                if ($id) { // Récupérer un diagnostic spécifique
                    $stmt = $pdo->prepare("SELECT * FROM diagnoses WHERE diagnose_id = ?");
                    $stmt->execute([$id]);
                    $diagnosis = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($diagnosis) { sendResponse($diagnosis); }
                    else { sendResponse(["error" => "Diagnosis not found."], 404); }
                } else { // Récupérer tous les diagnostics ou par patient_id
                    $patient_id = $_GET['patient_id'] ?? null;
                    if ($patient_id) {
                        $stmt = $pdo->prepare("SELECT * FROM diagnoses WHERE patient_id = ?");
                        $stmt->execute([$patient_id]);
                    } else {
                        $stmt = $pdo->query("SELECT * FROM diagnoses");
                    }
                    $diagnoses = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($diagnoses);
                }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'POST') {
            $required_fields = ['patient_id', 'date_diagnostic', 'description'];
            foreach ($required_fields as $field) {
                if (!isset($input[$field])) { sendResponse(["error" => "Missing field: $field"], 400); }
            }
            try {
                $stmt = $pdo->prepare("INSERT INTO diagnoses (patient_id, medecin_id, date_diagnostic, code_cim, description, gravite) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$input['patient_id'], $input['medecin_id'] ?? null, $input['date_diagnostic'], $input['code_cim'] ?? null, $input['description'], $input['gravite'] ?? null]);
                sendResponse(["message" => "Diagnosis added successfully!", "diagnose_id" => $pdo->lastInsertId()], 201);
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'PUT') {
            if (!$id) { sendResponse(["error" => "Diagnosis ID is required for update."], 400); }
            $updateFields = [];
            $updateValues = [];
            if (isset($input['patient_id'])) { $updateFields[] = "patient_id = ?"; $updateValues[] = $input['patient_id']; }
            if (isset($input['medecin_id'])) { $updateFields[] = "medecin_id = ?"; $updateValues[] = $input['medecin_id']; }
            if (isset($input['date_diagnostic'])) { $updateFields[] = "date_diagnostic = ?"; $updateValues[] = $input['date_diagnostic']; }
            if (isset($input['code_cim'])) { $updateFields[] = "code_cim = ?"; $updateValues[] = $input['code_cim']; }
            if (isset($input['description'])) { $updateFields[] = "description = ?"; $updateValues[] = $input['description']; }
            if (isset($input['gravite'])) { $updateFields[] = "gravite = ?"; $updateValues[] = $input['gravite']; }

            if (empty($updateFields)) { sendResponse(["error" => "No data provided for update."], 400); }
            $query = "UPDATE diagnoses SET " . implode(", ", $updateFields) . " WHERE diagnose_id = ?";
            $updateValues[] = $id;
            try {
                $stmt = $pdo->prepare($query);
                $stmt->execute($updateValues);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Diagnosis updated successfully!"]); }
                else { sendResponse(["error" => "Diagnosis not found or no changes made."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'DELETE') {
            if (!$id) { sendResponse(["error" => "Diagnosis ID is required for deletion."], 400); }
            try {
                $stmt = $pdo->prepare("DELETE FROM diagnoses WHERE diagnose_id = ?");
                $stmt->execute([$id]);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Diagnosis deleted successfully!"]); }
                else { sendResponse(["error" => "Diagnosis not found."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } else { sendResponse(["error" => "Method not allowed for /diagnoses."], 405); }
        break;

    case 'observations':
        isAuthenticated(['medecin']); // Seuls les médecins peuvent gérer les observations
        if ($method === 'GET') {
            try {
                if ($id) { // Récupérer une observation spécifique
                    $stmt = $pdo->prepare("SELECT * FROM observations WHERE observation_id = ?");
                    $stmt->execute([$id]);
                    $observation = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($observation) { sendResponse($observation); }
                    else { sendResponse(["error" => "Observation not found."], 404); }
                } else { // Récupérer toutes les observations ou par patient_id
                    $patient_id = $_GET['patient_id'] ?? null;
                    if ($patient_id) {
                        $stmt = $pdo->prepare("SELECT * FROM observations WHERE patient_id = ?");
                        $stmt->execute([$patient_id]);
                    } else {
                        $stmt = $pdo->query("SELECT * FROM observations");
                    }
                    $observations = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($observations);
                }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'POST') {
            $required_fields = ['patient_id', 'type_observation', 'valeur'];
            foreach ($required_fields as $field) {
                if (!isset($input[$field])) { sendResponse(["error" => "Missing field: $field"], 400); }
            }
            try {
                $stmt = $pdo->prepare("INSERT INTO observations (patient_id, medecin_id, date_observation, type_observation, valeur, unite, notes) VALUES (?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([$input['patient_id'], $input['medecin_id'] ?? null, $input['date_observation'] ?? date('Y-m-d H:i:s'), $input['type_observation'], $input['valeur'], $input['unite'] ?? null, $input['notes'] ?? null]);
                sendResponse(["message" => "Observation added successfully!", "observation_id" => $pdo->lastInsertId()], 201);
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'PUT') {
            if (!$id) { sendResponse(["error" => "Observation ID is required for update."], 400); }
            $updateFields = [];
            $updateValues = [];
            if (isset($input['patient_id'])) { $updateFields[] = "patient_id = ?"; $updateValues[] = $input['patient_id']; }
            if (isset($input['medecin_id'])) { $updateFields[] = "medecin_id = ?"; $updateValues[] = $input['medecin_id']; }
            if (isset($input['date_observation'])) { $updateFields[] = "date_observation = ?"; $updateValues[] = $input['date_observation']; }
            if (isset($input['type_observation'])) { $updateFields[] = "type_observation = ?"; $updateValues[] = $input['type_observation']; }
            if (isset($input['valeur'])) { $updateFields[] = "valeur = ?"; $updateValues[] = $input['valeur']; }
            if (isset($input['unite'])) { $updateFields[] = "unite = ?"; $updateValues[] = $input['unite']; }
            if (isset($input['notes'])) { $updateFields[] = "notes = ?"; $updateValues[] = $input['notes']; }

            if (empty($updateFields)) { sendResponse(["error" => "No data provided for update."], 400); }
            $query = "UPDATE observations SET " . implode(", ", $updateFields) . " WHERE observation_id = ?";
            $updateValues[] = $id;
            try {
                $stmt = $pdo->prepare($query);
                $stmt->execute($updateValues);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Observation updated successfully!"]); }
                else { sendResponse(["error" => "Observation not found or no changes made."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'DELETE') {
            if (!$id) { sendResponse(["error" => "Observation ID is required for deletion."], 400); }
            try {
                $stmt = $pdo->prepare("DELETE FROM observations WHERE observation_id = ?");
                $stmt->execute([$id]);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Observation deleted successfully!"]); }
                else { sendResponse(["error" => "Observation not found."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } else { sendResponse(["error" => "Method not allowed for /observations."], 405); }
        break;

    case 'prescriptions':
        isAuthenticated(['medecin']); // Seuls les médecins peuvent gérer les prescriptions
        if ($method === 'GET') {
            try {
                if ($id) { // Récupérer une prescription spécifique
                    $stmt = $pdo->prepare("SELECT * FROM prescriptions WHERE prescription_id = ?");
                    $stmt->execute([$id]);
                    $prescription = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($prescription) { sendResponse($prescription); }
                    else { sendResponse(["error" => "Prescription not found."], 404); }
                } else { // Récupérer toutes les prescriptions ou par patient_id
                    $patient_id = $_GET['patient_id'] ?? null;
                    if ($patient_id) {
                        $stmt = $pdo->prepare("SELECT p.*, m.nom_article AS nom_medicament_ref FROM prescriptions p LEFT JOIN inventaire m ON p.medicament_id = m.article_id WHERE p.patient_id = ?");
                        $stmt->execute([$patient_id]);
                    } else {
                        $stmt = $pdo->query("SELECT p.*, m.nom_article AS nom_medicament_ref FROM prescriptions p LEFT JOIN inventaire m ON p.medicament_id = m.article_id");
                    }
                    $prescriptions = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($prescriptions);
                }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'POST') {
            $required_fields = ['patient_id', 'medecin_id', 'date_prescription'];
            foreach ($required_fields as $field) {
                if (!isset($input[$field])) { sendResponse(["error" => "Missing field: $field"], 400); }
            }
            if (!isset($input['medicament_id']) && !isset($input['nom_medicament_texte'])) {
                sendResponse(["error" => "Either medicament_id or nom_medicament_texte is required."], 400);
            }

            try {
                $stmt = $pdo->prepare("INSERT INTO prescriptions (patient_id, medecin_id, medicament_id, nom_medicament_texte, date_prescription, quantite, instructions) VALUES (?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([$input['patient_id'], $input['medecin_id'], $input['medicament_id'] ?? null, $input['nom_medicament_texte'] ?? null, $input['date_prescription'], $input['quantite'] ?? null, $input['instructions'] ?? null]);
                sendResponse(["message" => "Prescription added successfully!", "prescription_id" => $pdo->lastInsertId()], 201);
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'PUT') {
            if (!$id) { sendResponse(["error" => "Prescription ID is required for update."], 400); }
            $updateFields = [];
            $updateValues = [];
            if (isset($input['patient_id'])) { $updateFields[] = "patient_id = ?"; $updateValues[] = $input['patient_id']; }
            if (isset($input['medecin_id'])) { $updateFields[] = "medecin_id = ?"; $updateValues[] = $input['medecin_id']; }
            if (isset($input['medicament_id'])) { $updateFields[] = "medicament_id = ?"; $updateValues[] = $input['medicament_id']; }
            if (isset($input['nom_medicament_texte'])) { $updateFields[] = "nom_medicament_texte = ?"; $updateValues[] = $input['nom_medicament_texte']; }
            if (isset($input['date_prescription'])) { $updateFields[] = "date_prescription = ?"; $updateValues[] = $input['date_prescription']; }
            if (isset($input['quantite'])) { $updateFields[] = "quantite = ?"; $updateValues[] = $input['quantite']; }
            if (isset($input['instructions'])) { $updateFields[] = "instructions = ?"; $updateValues[] = $input['instructions']; }

            if (empty($updateFields)) { sendResponse(["error" => "No data provided for update."], 400); }
            $query = "UPDATE prescriptions SET " . implode(", ", $updateFields) . " WHERE prescription_id = ?";
            $updateValues[] = $id;
            try {
                $stmt = $pdo->prepare($query);
                $stmt->execute($updateValues);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Prescription updated successfully!"]); }
                else { sendResponse(["error" => "Prescription not found or no changes made."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'DELETE') {
            if (!$id) { sendResponse(["error" => "Prescription ID is required for deletion."], 400); }
            try {
                $stmt = $pdo->prepare("DELETE FROM prescriptions WHERE prescription_id = ?");
                $stmt->execute([$id]);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Prescription deleted successfully!"]); }
                else { sendResponse(["error" => "Prescription not found."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } else { sendResponse(["error" => "Method not allowed for /prescriptions."], 405); }
        break;

    case 'tests-laboratoire':
        isAuthenticated(['medecin', 'lab_agent']); // Médecin et agent labo peuvent gérer
        if ($method === 'GET') {
            try {
                if ($id) { // Récupérer un test spécifique
                    $stmt = $pdo->prepare("SELECT * FROM tests_laboratoire WHERE test_id = ?");
                    $stmt->execute([$id]);
                    $test = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($test) { sendResponse($test); }
                    else { sendResponse(["error" => "Lab test not found."], 404); }
                } else { // Récupérer tous les tests ou par patient_id
                    $patient_id = $_GET['patient_id'] ?? null;
                    if ($patient_id) {
                        $stmt = $pdo->prepare("SELECT * FROM tests_laboratoire WHERE patient_id = ?");
                        $stmt->execute([$patient_id]);
                    } else {
                        $stmt = $pdo->query("SELECT * FROM tests_laboratoire");
                    }
                    $tests = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($tests);
                }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'POST') {
            isAuthenticated(['medecin']); // Seuls les médecins peuvent demander des tests
            $required_fields = ['patient_id', 'type_test', 'date_demande'];
            foreach ($required_fields as $field) {
                if (!isset($input[$field])) { sendResponse(["error" => "Missing field: $field"], 400); }
            }
            try {
                $stmt = $pdo->prepare("INSERT INTO tests_laboratoire (patient_id, type_test, date_demande, date_resultat, resultats, notes, statut) VALUES (?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([$input['patient_id'], $input['type_test'], $input['date_demande'], $input['date_resultat'] ?? null, $input['resultats'] ?? null, $input['notes'] ?? null, $input['statut'] ?? 'En attente']);
                sendResponse(["message" => "Lab test requested successfully!", "test_id" => $pdo->lastInsertId()], 201);
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'PUT') {
            isAuthenticated(['lab_agent']); // Seuls les agents labo peuvent modifier les tests
            if (!$id) { sendResponse(["error" => "Lab test ID is required for update."], 400); }
            $updateFields = [];
            $updateValues = [];
            if (isset($input['patient_id'])) { $updateFields[] = "patient_id = ?"; $updateValues[] = $input['patient_id']; }
            if (isset($input['type_test'])) { $updateFields[] = "type_test = ?"; $updateValues[] = $input['type_test']; }
            if (isset($input['date_demande'])) { $updateFields[] = "date_demande = ?"; $updateValues[] = $input['date_demande']; }
            if (array_key_exists('date_resultat', $input)) { $updateFields[] = "date_resultat = ?"; $updateValues[] = $input['date_resultat']; }
            if (array_key_exists('resultats', $input)) { $updateFields[] = "resultats = ?"; $updateValues[] = $input['resultats']; }
            if (array_key_exists('notes', $input)) { $updateFields[] = "notes = ?"; $updateValues[] = $input['notes']; }
            if (isset($input['statut'])) { $updateFields[] = "statut = ?"; $updateValues[] = $input['statut']; }

            if (empty($updateFields)) { sendResponse(["error" => "No data provided for update."], 400); }
            $query = "UPDATE tests_laboratoire SET " . implode(", ", $updateFields) . " WHERE test_id = ?";
            $updateValues[] = $id;
            try {
                $stmt = $pdo->prepare($query);
                $stmt->execute($updateValues);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Lab test updated successfully!"]); }
                else { sendResponse(["error" => "Lab test not found or no changes made."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'DELETE') {
            isAuthenticated(['lab_agent']); // Seuls les agents labo peuvent supprimer des tests
            if (!$id) { sendResponse(["error" => "Lab test ID is required for deletion."], 400); }
            try {
                $stmt = $pdo->prepare("DELETE FROM tests_laboratoire WHERE test_id = ?");
                $stmt->execute([$id]);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Lab test deleted successfully!"]); }
                else { sendResponse(["error" => "Lab test not found."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } else { sendResponse(["error" => "Method not allowed for /tests-laboratoire."], 405); }
        break;

    case 'emergency-queue':
        isAuthenticated(['secretaire', 'medecin']); // Secrétaire et médecin peuvent gérer
        if ($method === 'GET') {
            try {
                if ($id) {
                    $stmt = $pdo->prepare("SELECT eq.*, p.nom, p.prenom FROM emergency_queue eq JOIN patients p ON eq.patient_id = p.patient_id WHERE eq.queue_id = ?");
                    $stmt->execute([$id]);
                    $item = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($item) { sendResponse($item); }
                    else { sendResponse(["error" => "Queue item not found."], 404); }
                } else {
                    $stmt = $pdo->query("SELECT eq.*, p.nom, p.prenom FROM emergency_queue eq JOIN patients p ON eq.patient_id = p.patient_id ORDER BY entry_time ASC");
                    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($items);
                }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'POST') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent ajouter à la file
            $required_fields = ['patient_id'];
            foreach ($required_fields as $field) {
                if (!isset($input[$field])) { sendResponse(["error" => "Missing field: $field"], 400); }
            }
            try {
                $stmt = $pdo->prepare("INSERT INTO emergency_queue (patient_id, notes, status) VALUES (?, ?, ?)");
                $stmt->execute([$input['patient_id'], $input['notes'] ?? null, $input['status'] ?? 'En attente']);
                sendResponse(["message" => "Patient added to emergency queue!", "queue_id" => $pdo->lastInsertId()], 201);
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'PUT') {
            isAuthenticated(['secretaire', 'medecin']); // Secrétaire et médecin peuvent modifier le statut
            if (!$id) { sendResponse(["error" => "Queue ID is required for update."], 400); }
            $updateFields = [];
            $updateValues = [];
            if (isset($input['status'])) { $updateFields[] = "status = ?"; $updateValues[] = $input['status']; }
            if (isset($input['notes'])) { $updateFields[] = "notes = ?"; $updateValues[] = $input['notes']; }

            if (empty($updateFields)) { sendResponse(["error" => "No data provided for update."], 400); }
            $query = "UPDATE emergency_queue SET " . implode(", ", $updateFields) . " WHERE queue_id = ?";
            $updateValues[] = $id;
            try {
                $stmt = $pdo->prepare($query);
                $stmt->execute($updateValues);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Emergency queue item updated successfully!"]); }
                else { sendResponse(["error" => "Queue item not found or no changes made."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'DELETE') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent supprimer de la file
            if (!$id) { sendResponse(["error" => "Queue ID is required for deletion."], 400); }
            try {
                $stmt = $pdo->prepare("DELETE FROM emergency_queue WHERE queue_id = ?");
                $stmt->execute([$id]);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Patient removed from emergency queue!"]); }
                else { sendResponse(["error" => "Queue item not found."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } else { sendResponse(["error" => "Method not allowed for /emergency-queue."], 405); }
        break;

    case 'operations':
        isAuthenticated(['secretaire', 'medecin']);
        if ($method === 'GET') {
            try {
                if ($id) {
                    $stmt = $pdo->prepare("SELECT * FROM operations WHERE operation_id = ?");
                    $stmt->execute([$id]);
                    $operation = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($operation) { sendResponse($operation); }
                    else { sendResponse(["error" => "Operation not found."], 404); }
                } else {
                    $stmt = $pdo->query("SELECT * FROM operations");
                    $operations = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($operations);
                }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'POST') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent planifier les opérations
            $required_fields = ['patient_id', 'medecin_id', 'procedure_name', 'date_operation', 'heure_debut'];
            foreach ($required_fields as $field) {
                if (!isset($input[$field])) { sendResponse(["error" => "Missing field: $field"], 400); }
            }
            try {
                $stmt = $pdo->prepare("INSERT INTO operations (patient_id, medecin_id, procedure_name, date_operation, heure_debut, heure_fin, salle_operation, personnel_notes, statut) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([$input['patient_id'], $input['medecin_id'], $input['procedure_name'], $input['date_operation'], $input['heure_debut'], $input['heure_fin'] ?? null, $input['salle_operation'] ?? null, $input['personnel_notes'] ?? null, $input['statut'] ?? 'Planifiée']);
                sendResponse(["message" => "Operation scheduled successfully!", "operation_id" => $pdo->lastInsertId()], 201);
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'PUT') {
             isAuthenticated(['secretaire', 'medecin']); // Secrétaire et médecin peuvent modifier les opérations
            if (!$id) { sendResponse(["error" => "Operation ID is required for update."], 400); }
            $updateFields = [];
            $updateValues = [];
            if (isset($input['patient_id'])) { $updateFields[] = "patient_id = ?"; $updateValues[] = $input['patient_id']; }
            if (isset($input['medecin_id'])) { $updateFields[] = "medecin_id = ?"; $updateValues[] = $input['medecin_id']; }
            if (isset($input['procedure_name'])) { $updateFields[] = "procedure_name = ?"; $updateValues[] = $input['procedure_name']; }
            if (isset($input['date_operation'])) { $updateFields[] = "date_operation = ?"; $updateValues[] = $input['date_operation']; }
            if (isset($input['heure_debut'])) { $updateFields[] = "heure_debut = ?"; $updateValues[] = $input['heure_debut']; }
            if (array_key_exists('heure_fin', $input)) { $updateFields[] = "heure_fin = ?"; $updateValues[] = $input['heure_fin']; }
            if (array_key_exists('salle_operation', $input)) { $updateFields[] = "salle_operation = ?"; $updateValues[] = $input['salle_operation']; }
            if (array_key_exists('personnel_notes', $input)) { $updateFields[] = "personnel_notes = ?"; $updateValues[] = $input['personnel_notes']; }
            if (isset($input['statut'])) { $updateFields[] = "statut = ?"; $updateValues[] = $input['statut']; }

            if (empty($updateFields)) { sendResponse(["error" => "No data provided for update."], 400); }
            $query = "UPDATE operations SET " . implode(", ", $updateFields) . " WHERE operation_id = ?";
            $updateValues[] = $id;
            try {
                $stmt = $pdo->prepare($query);
                $stmt->execute($updateValues);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Operation updated successfully!"]); }
                else { sendResponse(["error" => "Operation not found or no changes made."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'DELETE') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent supprimer les opérations
            if (!$id) { sendResponse(["error" => "Operation ID is required for deletion."], 400); }
            try {
                $stmt = $pdo->prepare("DELETE FROM operations WHERE operation_id = ?");
                $stmt->execute([$id]);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Operation deleted successfully!"]); }
                else { sendResponse(["error" => "Operation not found."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } else { sendResponse(["error" => "Method not allowed for /operations."], 405); }
        break;

    case 'appointments':
        isAuthenticated(['secretaire', 'medecin']);
        if ($method === 'GET') {
            try {
                if ($id) {
                    $stmt = $pdo->prepare("SELECT * FROM appointments WHERE rendezvous_id = ?");
                    $stmt->execute([$id]);
                    $appointment = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($appointment) { sendResponse($appointment); }
                    else { sendResponse(["error" => "Appointment not found."], 404); }
                } else {
                    $stmt = $pdo->query("SELECT * FROM appointments");
                    $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($appointments);
                }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'POST') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent planifier les rendez-vous
            $required_fields = ['patient_id', 'date_heure', 'raison'];
            foreach ($required_fields as $field) {
                if (!isset($input[$field])) { sendResponse(["error" => "Missing field: $field"], 400); }
            }
            try {
                $stmt = $pdo->prepare("INSERT INTO appointments (patient_id, medecin_id, date_heure, raison, statut) VALUES (?, ?, ?, ?, ?)");
                $stmt->execute([$input['patient_id'], $input['medecin_id'] ?? null, $input['date_heure'], $input['raison'], $input['statut'] ?? 'Planifié']);
                sendResponse(["message" => "Appointment scheduled successfully!", "rendezvous_id" => $pdo->lastInsertId()], 201);
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'PUT') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent modifier les rendez-vous
            if (!$id) { sendResponse(["error" => "Appointment ID is required for update."], 400); }
            $updateFields = [];
            $updateValues = [];
            if (isset($input['patient_id'])) { $updateFields[] = "patient_id = ?"; $updateValues[] = $input['patient_id']; }
            if (isset($input['medecin_id'])) { $updateFields[] = "medecin_id = ?"; $updateValues[] = $input['medecin_id']; }
            if (isset($input['date_heure'])) { $updateFields[] = "date_heure = ?"; $updateValues[] = $input['date_heure']; }
            if (isset($input['raison'])) { $updateFields[] = "raison = ?"; $updateValues[] = $input['raison']; }
            if (isset($input['statut'])) { $updateFields[] = "statut = ?"; $updateValues[] = $input['statut']; }

            if (empty($updateFields)) { sendResponse(["error" => "No data provided for update."], 400); }
            $query = "UPDATE appointments SET " . implode(", ", $updateFields) . " WHERE rendezvous_id = ?";
            $updateValues[] = $id;
            try {
                $stmt = $pdo->prepare($query);
                $stmt->execute($updateValues);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Appointment updated successfully!"]); }
                else { sendResponse(["error" => "Appointment not found or no changes made."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'DELETE') {
            isAuthenticated(['secretaire']); // Seules les secrétaires peuvent supprimer les rendez-vous
            if (!$id) { sendResponse(["error" => "Appointment ID is required for deletion."], 400); }
            try {
                $stmt = $pdo->prepare("DELETE FROM appointments WHERE rendezvous_id = ?");
                $stmt->execute([$id]);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Appointment deleted successfully!"]); }
                else { sendResponse(["error" => "Appointment not found."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } else { sendResponse(["error" => "Method not allowed for /appointments."], 405); }
        break;

    case 'disponibilites':
        isAuthenticated(['secretaire']); // Seules les secrétaires peuvent gérer les disponibilités
        if ($method === 'GET') {
            try {
                if ($id) {
                    $stmt = $pdo->prepare("SELECT d.*, m.nom, m.prenom FROM disponibilites d JOIN medecins m ON d.medecin_id = m.medecin_id WHERE d.disponibilite_id = ?");
                    $stmt->execute([$id]);
                    $disponibilite = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($disponibilite) { sendResponse($disponibilite); }
                    else { sendResponse(["error" => "Availability not found."], 404); }
                } else {
                    // Joindre la table des médecins pour afficher le nom/prénom
                    $stmt = $pdo->query("SELECT d.*, m.nom, m.prenom FROM disponibilites d JOIN medecins m ON d.medecin_id = m.medecin_id ORDER BY d.date_disponibilite, d.heure_debut ASC");
                    $disponibilites = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    sendResponse($disponibilites);
                }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'POST') {
            $required_fields = ['medecin_id', 'date_disponibilite', 'heure_debut', 'heure_fin'];
            foreach ($required_fields as $field) {
                if (!isset($input[$field])) { sendResponse(["error" => "Missing field: $field"], 400); }
            }
            try {
                $stmt = $pdo->prepare("INSERT INTO disponibilites (medecin_id, date_disponibilite, heure_debut, heure_fin, statut, notes) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$input['medecin_id'], $input['date_disponibilite'], $input['heure_debut'], $input['heure_fin'], $input['statut'] ?? 'Disponible', $input['notes'] ?? null]);
                sendResponse(["message" => "Availability added successfully!", "disponibilite_id" => $pdo->lastInsertId()], 201);
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'PUT') {
            if (!$id) { sendResponse(["error" => "Availability ID is required for update."], 400); }
            $updateFields = [];
            $updateValues = [];
            if (isset($input['medecin_id'])) { $updateFields[] = "medecin_id = ?"; $updateValues[] = $input['medecin_id']; }
            if (isset($input['date_disponibilite'])) { $updateFields[] = "date_disponibilite = ?"; $updateValues[] = $input['date_disponibilite']; }
            if (isset($input['heure_debut'])) { $updateFields[] = "heure_debut = ?"; $updateValues[] = $input['heure_debut']; }
            if (isset($input['heure_fin'])) { $updateFields[] = "heure_fin = ?"; $updateValues[] = $input['heure_fin']; }
            if (isset($input['statut'])) { $updateFields[] = "statut = ?"; $updateValues[] = $input['statut']; }
            if (isset($input['notes'])) { $updateFields[] = "notes = ?"; $updateValues[] = $input['notes']; }

            if (empty($updateFields)) { sendResponse(["error" => "No data provided for update."], 400); }
            $query = "UPDATE disponibilites SET " . implode(", ", $updateFields) . " WHERE disponibilite_id = ?";
            $updateValues[] = $id;
            try {
                $stmt = $pdo->prepare($query);
                $stmt->execute($updateValues);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Availability updated successfully!"]); }
                else { sendResponse(["error" => "Availability not found or no changes made."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } elseif ($method === 'DELETE') {
            if (!$id) { sendResponse(["error" => "Availability ID is required for deletion."], 400); }
            try {
                $stmt = $pdo->prepare("DELETE FROM disponibilites WHERE disponibilite_id = ?");
                $stmt->execute([$id]);
                if ($stmt->rowCount() > 0) { sendResponse(["message" => "Availability deleted successfully!"]); }
                else { sendResponse(["error" => "Availability not found."], 404); }
            } catch (PDOException $e) { sendResponse(["error" => "Database error: " . $e->getMessage()], 500); }
        } else { sendResponse(["error" => "Method not allowed for /disponibilites."], 405); }
        break;

    default:
        sendResponse(["error" => "Resource not found."], 404);
        break;
}

// Assure que le script s'arrête ici
exit();
?>
