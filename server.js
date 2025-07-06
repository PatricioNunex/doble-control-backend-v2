require("dotenv").config();


const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

// URI de conexión a MongoDB Atlas
const mongoURI = "mongodb+srv://pnunez:pat2030@primera.1ixlimm.mongodb.net/entregasCarnes?retryWrites=true&w=majority&appName=primera";

// Conexión
mongoose.connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("✅ Conectado a MongoDB Atlas"))
  .catch(err => console.error("❌ Error al conectar:", err));

// Esquemas
const RecepcionSchema = new mongoose.Schema({}, { strict: false });
const Recepcion = mongoose.model("Doble control de carnes", RecepcionSchema, "Doble control de carnes");

const UserSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: true, 
        unique: true,
        trim: true,
        minlength: 3
    },
    password: { 
        type: String, 
        required: true,
        minlength: 6
    },
    role: { 
        type: String, 
        enum: ['admin', 'operador'], 
        default: 'operador' 
    },
    firstLogin: {
        type: Boolean,
        default: true
    }
}, { timestamps: true });

// Hash de contraseña antes de guardar
UserSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

// Método para comparar contraseñas
UserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', UserSchema);

const app = express();
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());

// Middleware de autenticación
const authenticate = async (req, res, next) => {
    try {
        const token = req.header('Authorization').replace('Bearer ', '');
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret_key');
        const user = await User.findOne({ _id: decoded._id });
        
        if (!user) {
            throw new Error();
        }

        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).send({ error: 'Acceso no autorizado' });
    }
};

// Middleware para admin
const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send({ error: 'Acceso denegado. Se requiere rol de administrador' });
    }
    next();
};

// Ruta de prueba
app.get("/", (req, res) => {
    res.send("API de Control de Carnes funcionando 🎉");
});

// Ruta para recibir pallets
app.post("/recepcion", async (req, res) => {
    try {
        const nuevaRecepcion = new Recepcion(req.body);
        await nuevaRecepcion.save();
        res.status(201).json({ mensaje: "Recepción guardada correctamente ✅" });
    } catch (err) {
        console.error("❌ Error al guardar:", err);
        res.status(500).json({ error: "Error al guardar recepción" });
    }
});

// Ruta para crear usuario inicial (solo para primera ejecución)
app.post("/init", async (req, res) => {
    try {
        const adminUser = {
            username: "admin",
            password: "admin123",
            role: "admin"
        };
        
        const user = new User(adminUser);
        await user.save();
        
        res.status(201).json({ 
            message: "Usuario admin creado exitosamente",
            user: { username: user.username, role: user.role }
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Ruta de login
app.post("/usuarios/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        
        if (!user) {
            return res.status(400).json({ error: "Credenciales inválidas" });
        }
        
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(400).json({ error: "Credenciales inválidas" });
        }
        
        const token = jwt.sign(
            { _id: user._id.toString(), username: user.username, role: user.role }, 
            process.env.JWT_SECRET || 'secret_key',
            { expiresIn: '8h' }
        );
        
        res.json({
            token,
            username: user.username,
            role: user.role,
            firstLogin: user.firstLogin
        });
    } catch (error) {
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// Ruta para cambiar contraseña
app.post("/usuarios/cambiar-password", authenticate, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = req.user;
        
        const isMatch = await user.comparePassword(currentPassword);
        if (!isMatch) {
            return res.status(400).json({ error: "Contraseña actual incorrecta" });
        }
        
        user.password = newPassword;
        user.firstLogin = false;
        await user.save();
        
        res.json({ message: "Contraseña actualizada exitosamente" });
    } catch (error) {
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// Ruta para obtener usuarios (solo admin)
app.get("/usuarios", authenticate, isAdmin, async (req, res) => {
    try {
        const users = await User.find({}, '-password');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: "Error al obtener usuarios" });
    }
});

// Ruta para crear usuario (solo admin)
app.post("/usuarios", authenticate, isAdmin, async (req, res) => {
    try {
        const { username, password, role } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: "Usuario y contraseña son obligatorios" });
        }
        
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: "El usuario ya existe" });
        }
        
        const newUser = new User({ username, password, role });
        await newUser.save();
        
        res.status(201).json({ 
            message: "Usuario creado exitosamente",
            user: { username: newUser.username, role: newUser.role }
        });
    } catch (error) {
        res.status(500).json({ error: "Error al crear usuario" });
    }
});

// Ruta para actualizar usuario (solo admin)
app.put("/usuarios/:id", authenticate, isAdmin, async (req, res) => {
    try {
        const { password, role } = req.body;
        const user = await User.findById(req.params.id);
        
        if (!user) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }
        
        if (password) user.password = password;
        if (role) user.role = role;
        
        await user.save();
        res.json({ message: "Usuario actualizado exitosamente" });
    } catch (error) {
        res.status(500).json({ error: "Error al actualizar usuario" });
    }
});

// Ruta para eliminar usuario (solo admin)
app.delete("/usuarios/:id", authenticate, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        
        if (!user) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }
        
        if (user.role === 'admin') {
            const adminCount = await User.countDocuments({ role: 'admin' });
            if (adminCount === 1) {
                return res.status(400).json({ error: "No se puede eliminar el último administrador" });
            }
        }
        
        await user.deleteOne();
        res.json({ message: "Usuario eliminado exitosamente" });
    } catch (error) {
        res.status(500).json({ error: "Error al eliminar usuario" });
    }
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor corriendo en puerto ${PORT}`));

