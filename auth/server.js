const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const serviceAccount = {
  type: process.env.TYPE,
  project_id: process.env.PROJECT_ID,
  private_key_id: process.env.PRIVATE_KEY_ID,
  private_key: process.env.PRIVATE_KEY.replace(/\\n/g, "\n"),
  client_email: process.env.CLIENT_EMAIL,
  client_id: process.env.CLIENT_ID,
  auth_uri: process.env.AUTH_URI,
  token_uri: process.env.TOKEN_URI,
  auth_provider_x509_cert_url: process.env.AUTH_PROVIDER_CERT_URL,
  client_x509_cert_url: process.env.CLIENT_CERT_URL,
  universe_domain: process.env.UNIVERSE_DOMAIN,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const app = express();
const PORT = process.env.AUTH_SERVICE_PORT || 5001;

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Auth service running!");
});

// Auth routes
// Auth routes
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Buscar que el usuario exista en Firestore
    const usersRef = db.collection("users");
    const buscardo = await usersRef.where("email", "==", email).get();

    if (buscardo.empty) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    let user;
    let userId;
    buscardo.forEach((doc) => {
      user = doc.data();
      userId = doc.id;
    });

    // Verificación de la contraseña
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (isPasswordValid) {
      // Generar token con expiración de 10 minutos
      const token = jwt.sign(
        { id: userId, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "10m" }
      );

      // Guardar token en Firestore con expiración en formato ISO 8601
      const tokensRef = db.collection("tokensVerification");
      const expirationTime = new Date(
        Date.now() + 10 * 60 * 1000
      ).toISOString(); // Formato ISO 8601

      await tokensRef.add({
        token,
        userId,
        expiresAt: expirationTime, // Guardar en formato ISO 8601
      });

      return res.status(200).json({
        message: "Inicio de sesión exitoso",
        token, // Enviamos el token generado al cliente
        role: user.role,
        user: { ...user, id: userId, role: user.role },
      });
    } else {
      return res.status(401).json({ message: "Contraseña incorrecta" });
    }
  } catch (error) {
    console.error("Error en el login:", error);
    return res.status(500).json({ message: "Error en el servidor" });
  }
});

app.post("/register", async (req, res) => {
  const { username, fullName, birthDate, email, password } = req.body;

  try {
    //Verificamos si el usuario ya existe
    const usersRef = db.collection("users");
    const snapshot = await usersRef.where("email", "==", email).get();

    if (!snapshot.empty) {
      return res.status(400).json({ message: "El correo ya está registrado" });
    }

    //Hasheo de la contraseña
    const saltRounds = 10; //Número de rondas de hasheo
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    //Creamos un nuevo usuario en la base de datos
    const newUser = {
      username,
      fullName,
      birthDate,
      email,
      password: hashedPassword,
      role: "mortal",
    };

    //Mandamos el nuevo usuario para su registro en la colección
    await usersRef.add(newUser);
    return res.status(201).json({ message: "Registro exitoso", user: newUser });
  } catch (error) {
    console.error("Error en el registro:", error);
    return res.status(500).json({ message: "Error en el servidor" });
  }
});

app.listen(PORT, () => {
  console.log(`Auth service running on http://localhost:${PORT}`);
});
