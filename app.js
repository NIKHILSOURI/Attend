import dotenv from 'dotenv';
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import bodyParser from 'body-parser';

// Initialize dotenv
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3030;

// Get current directory path for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost/attendance_tracker', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// Middleware
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static('public'));

// Models
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    }
}, { timestamps: true });

const attendanceSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    subject: {
        type: String,
        required: true,
        trim: true
    },
    totalClasses: {
        type: Number,
        required: true,
        min: 0
    },
    attendedClasses: {
        type: Number,
        required: true,
        min: 0
    },
    date: {
        type: Date,
        default: Date.now
    }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Attendance = mongoose.model('Attendance', attendanceSchema);

// Authentication middleware
const auth = async (req, res, next) => {
    try {
        const token = req.cookies.token || req.header('Authorization').replace('Bearer ', '');
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        req.user = await User.findById(decoded.id);
        next();
    } catch (error) {
        res.status(401).json({ message: 'Please authenticate' });
    }
};

// Auth routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 8);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(400).json({ message: 'Registration failed' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            throw new Error();
        }
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your-secret-key');
        res.cookie('token', token, { httpOnly: true });
        res.json({ token, name: user.name });
    } catch (error) {
        res.status(400).json({ message: 'Login failed' });
    }
});

// Attendance routes
app.post('/api/attendance', auth, async (req, res) => {
    try {
        const { subject, totalClasses, attendedClasses, date } = req.body;
        
        // Find existing attendance record or create new one
        let attendance = await Attendance.findOne({
            userId: req.user._id,
            subject: subject
        });

        if (attendance) {
            // Update existing record
            attendance.totalClasses = totalClasses;
            attendance.attendedClasses = attendedClasses;
            attendance.date = date;
            await attendance.save();
        } else {
            // Create new record
            attendance = new Attendance({
                userId: req.user._id,
                subject,
                totalClasses,
                attendedClasses,
                date
            });
            await attendance.save();
        }

        res.status(201).json(attendance);
    } catch (error) {
        console.error('Error saving attendance:', error);
        res.status(400).json({ message: 'Failed to save attendance' });
    }
});

app.get('/api/attendance', auth, async (req, res) => {
    try {
        const attendance = await Attendance.find({ 
            userId: req.user._id 
        }).sort({ subject: 1 });
        res.json(attendance);
    } catch (error) {
        res.status(400).json({ message: 'Failed to fetch attendance' });
    }
});

// Add this new route
app.get('/api/user/profile', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password');
        res.json(user);
    } catch (error) {
        res.status(400).json({ message: 'Failed to fetch user profile' });
    }
});

// Root route - redirects to home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Serve static files
app.use(express.static('public'));

// Handle all other routes to redirect to home
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Call the function when the database connects
mongoose.connection.on('connected', () => {
    console.log('Connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err);
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
