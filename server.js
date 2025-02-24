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

const verifyToken = (allowedRoles) => async (req, res, next) => {
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

    // Obtener el usuario desde la colección users
    const usersRef = db.collection("users");
    const userSnapshot = await usersRef.doc(tokenData.userId).get();

    if (!userSnapshot.exists) {
      console.log("Usuario no encontrado");
      return res.status(401).json({ message: "Usuario no encontrado." });
    }

    const userData = userSnapshot.data();
    console.log("Datos del usuario:", userData);

    if (!allowedRoles.includes(userData.role)) {
      console.log("Permisos insuficientes. Rol del usuario:", userData.role);
      return res
        .status(403)
        .json({ message: "Acceso denegado. Permisos insuficientes." });
    }

    console.log("Token verificado exitosamente");
    req.user = { id: tokenData.userId, role: userData.role };
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

//-------------------------------- TASKS PAGE --------------------------------//

//Obtener todas las tareas del usuario autenticado
app.get("/tasks", verifyToken(["admin", "mortal"]), async (req, res) => {
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

app.post("/add-tasks", verifyToken(["admin"], ["mortal"]), async (req, res) => {
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

//-------------------------------- GROUPS PAGE --------------------------------//

//Obtener todos los grupos a los que pertenece el usuario
app.get("/groups", verifyToken(["admin", "mortal"]), async (req, res) => {
  try {
    const groupsRef = db.collection("groups");

    //Consultar los grupos en los que el usuario es participante
    const groupsSnapshotByParticipant = await groupsRef
      .where("participantes", "array-contains", req.user.id)
      .get();

    //Consultar los grupos en los que el usuario es el creador
    const groupsSnapshotByCreator = await groupsRef
      .where("createdBy", "==", req.user.id)
      .get();

    const role = req.user.role;

    //Combinar los resultados de ambas consultas
    const groups = [];

    groupsSnapshotByParticipant.docs.forEach((doc) => {
      if (!groups.some((group) => group.id === doc.id)) {
        groups.push({
          id: doc.id,
          ...doc.data(),
        });
      }
    });

    groupsSnapshotByCreator.docs.forEach((doc) => {
      if (!groups.some((group) => group.id === doc.id)) {
        groups.push({
          id: doc.id,
          ...doc.data(),
        });
      }
    });

    if (groups.length === 0) {
      return res.status(200).json({ groups: [], role }); //Devuelve un array vacio si no hay grupos
    }

    return res.status(200).json({ groups, role });
  } catch (error) {
    console.error("Error al obtener los grupos:", error);
    return res
      .status(500)
      .json({ message: "Error en el servidor", error: error.message });
  }
});

app.get("/usersList", verifyToken(["admin", "mortal"]), async (req, res) => {
  try {
    const userIdToExclude = req.user.id; //ID del usuario autenticado

    const usersRef = db.collection("users");
    const usersSnapshot = await usersRef.get();

    if (usersSnapshot.empty) {
      return res.status(404).json({ message: "No se encontraron usuarios" });
    }

    const users = usersSnapshot.docs
      .map((doc) => ({
        id: doc.id,
        ...doc.data(),
      }))
      .filter((user) => user.id !== userIdToExclude);

    return res.status(200).json({ users });
  } catch (error) {
    console.error("Error al obtener usuarios:", error);
    return res.status(500).json({ message: "Error en el servidor" });
  }
});

app.post("/createGroup", verifyToken(["admin"]), async (req, res) => {
  try {
    const { name, participantes } = req.body;
    const createdBy = req.user.id;

    const groupRef = db.collection("groups");
    const newGroup = {
      name,
      participantes,
      createdBy,
      createdAt: new Date(),
    };

    const docRef = await groupRef.add(newGroup);
    return res.status(201).json({ group: { id: docRef.id, ...newGroup } });
  } catch (error) {
    console.error("Error al crear el grupo:", error);
    return res.status(500).json({ message: "Error en el servidor" });
  }
});

app.post("/groups/:groupId/addParticipant", verifyToken(["admin"]), async (req, res) => {
    try {
      const { groupId } = req.params;
      const { participantId } = req.body;

      const groupRef = db.collection("groups").doc(groupId);
      const groupDoc = await groupRef.get();

      if (!groupDoc.exists) {
        return res.status(404).json({ message: "Grupo no encontrado" });
      }

      const groupData = groupDoc.data();
      const updatedParticipants = [
        ...new Set([...groupData.participantes, participantId]),
      ];

      await groupRef.update({ participantes: updatedParticipants });

      res.status(200).json({ message: "Participante añadido con éxito" });
    } catch (error) {
      console.error("Error al añadir participante:", error);
      res.status(500).json({ message: "Error en el servidor" });
    }
  }
);

app.post("/createGroupTasks", verifyToken(["admin"]), async (req, res) => {
  try {
    const { name, description, category, status, assignedTo, groupId } =
      req.body;
    const createdBy = req.user.id;

    const taskRef = db.collection("tasks");
    const newTask = {
      name,
      description,
      category,
      status,
      assignedTo,
      groupId,
      createdBy,
      createdAt: new Date(),
    };

    const docRef = await taskRef.add(newTask);
    res.status(201).json({ task: { id: docRef.id, ...newTask } });
  } catch (error) {
    console.error("Error al crear la tarea:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

app.get("/groups/:groupId/tasks", verifyToken(["admin", "mortal"]), async (req, res) => {
  try {
    const { groupId } = req.params;
    const tasksRef = db.collection("tasks");
    const snapshot = await tasksRef.where("groupId", "==", groupId).get();

    if (snapshot.empty) {
      return res.status(200).json({ tasks: [], userRole: req.user.role, userId: req.user.id });
    }

    const tasks = [];
    snapshot.forEach(doc => {
      tasks.push({ id: doc.id, ...doc.data() });
    });

    res.status(200).json({ tasks, userRole: req.user.role, userId: req.user.id });
  } catch (error) {
    console.error("Error al obtener tareas:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

//Validación de actualización de la tarea
app.patch("/dropTasks/:taskId", verifyToken(["admin", "mortal"]), async (req, res) => {
  try {
    const { taskId } = req.params;
    const { status } = req.body;
    const userId = req.user.id;
    const userRole = req.user.role;

    const taskRef = db.collection("tasks").doc(taskId);
    const taskDoc = await taskRef.get();

    if (!taskDoc.exists) {
      return res.status(404).json({ message: "Tarea no encontrada" });
    }

    const taskData = taskDoc.data();

    //Verificamos que el usuario que hace la petición tenga permitido actualizar la tarea
    if (userRole !== "admin" && taskData.assignedTo !== userId) {
      return res.status(403).json({ message: "No tienes permiso para actualizar esta tarea" });
    }

    await taskRef.update({ status });

    res.status(200).json({ message: "Tarea actualizada con éxito" });
  } catch (error) {
    console.error("Error al actualizar la tarea:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

//Iniciar el servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
