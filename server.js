const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

require("dotenv").config();

var serviceAccount = require("./task-manager-credentials.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const app = express();

app.use(cors());
app.use(express.json());

//-------------------------------- MIDDLEWARE --------------------------------//

const verifyToken = () => async (req, res, next) => {
  console.log("Iniciando verificación de token");
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    console.log("Token no proporcionado");
    return res
      .status(401)
      .json({ message: "Acceso denegado. Token no proporcionado." });
  }

  console.log("Token recibido:", token);

  try {
    const tokensRef = db.collection("tokensVerification");
    const tokenSnapshot = await tokensRef.where("token", "==", token).get();

    if (tokenSnapshot.empty) {
      console.log("Token inválido o no encontrado");
      return res
        .status(401)
        .json({ message: "Token inválido o no encontrado." });
    }

    const tokenData = tokenSnapshot.docs[0].data();
    console.log("Datos del token:", tokenData);

    const now = new Date();
    if (new Date(tokenData.expiresAt) < now) {
      console.log("Token expirado");
      return res.status(401).json({ message: "Token ha expirado." });
    }

    console.log("Token verificado exitosamente");
    req.user = { id: tokenData.userId };
    next();
  } catch (error) {
    console.error("Error en la verificación del token:", error);
    res
      .status(500)
      .json({ message: "Error al verificar el token.", error: error.message });
  }
};

//-------------------------------- LOGIN PAGE --------------------------------//
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

//-------------------------------- REGISTER PAGE --------------------------------//

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
    };

    //Mandamos el nuevo usuario para su registro en la colección
    await usersRef.add(newUser);
    return res.status(201).json({ message: "Registro exitoso", user: newUser });
  } catch (error) {
    console.error("Error en el registro:", error);
    return res.status(500).json({ message: "Error en el servidor" });
  }
});

//-------------------------------- LOGIN PAGE --------------------------------//

//Obtener todas las tareas del usuario autenticado
app.get("/tasks", verifyToken(), async (req, res) => {
  try {
    const tasksRef = db.collection("tasks");
    const tasksSnapshot = await tasksRef
      .where("userId", "==", req.user.id)
      .get();

    if (tasksSnapshot.empty) {
      return res.status(404).json({ message: "No se encontraron tareas" });
    }

    const tasks = tasksSnapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));
    return res.status(200).json({ tasks });
  } catch (error) {
    console.error("Error al obtener las tareas:", error);
    return res
      .status(500)
      .json({ message: "Error en el servidor", error: error.message });
  }
});

app.post("/add-tasks", verifyToken(), async (req, res) => {
  const { name, description, dueDate, status, category } = req.body;

  try {
    const newTask = {
      name,
      description,
      dueDate,
      status,
      category,
      userId: req.user.id,
      createdAt: new Date(),
    };

    const tasksRef = db.collection("tasks");
    await tasksRef.add(newTask);

    return res
      .status(201)
      .json({ message: "Tarea añadida exitosamente", task: newTask });
  } catch (error) {
    console.error("Error al añadir la tarea:", error);
    return res
      .status(500)
      .json({ message: "Error en el servidor", error: error.message });
  }
});

//Iniciar el servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
