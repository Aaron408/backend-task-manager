const admin = require("firebase-admin");

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
    const db = admin.firestore();
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

module.exports = verifyToken;
