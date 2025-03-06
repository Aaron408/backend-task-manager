const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

require("dotenv").config();

var serviceAccount = require("../task-manager-credentials.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const app = express();

app.use(cors());
app.use(express.json());

// Auth routes
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    //Buscar que el usuario exista en Firestore
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

    //Verificación de la contraseña
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (isPasswordValid) {
      const token = jwt.sign(
        { id: userId, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "10m" }
      );

      //Guardamos el token del usuario
      const tokensRef = db.collection("tokensVerification");
      const expirationTime = new Date();
      expirationTime.setMinutes(expirationTime.getMinutes() + 10);

      await tokensRef.add({
        token,
        userId,
        expiresAt: expirationTime,
      });

      return res.status(200).json({
        message: "Inicio de sesión exitoso",
        token, //Enviamos el token generado al cliente
        user: { ...user, id: userId },
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

const PORT = process.env.AUTH_SERVICE_PORT || 5001;
app.listen(PORT, () => {
  console.log(`Auth service running on http://localhost:${PORT}`);
});
