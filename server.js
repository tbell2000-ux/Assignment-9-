const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, User, Project, Task } = require('./database/setup');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.SESSION_SECRET || 'your-jwt-secret';

app.use(express.json());



// General authentication middleware
function requireAuth(req, res, next) {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ error: 'Authorization header missing' });

        const token = authHeader.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'Token missing' });

        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // includes id, name, email, role
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// Manager + Admin access
function requireManager(req, res, next) {
    requireAuth(req, res, () => {
        if (req.user.role === 'manager' || req.user.role === 'admin') {
            next();
        } else {
            res.status(403).json({ error: 'Forbidden: Manager or Admin access required' });
        }
    });
}

// Admin-only access
function requireAdmin(req, res, next) {
    requireAuth(req, res, () => {
        if (req.user.role === 'admin') {
            next();
        } else {
            res.status(403).json({ error: 'Forbidden: Admin access required' });
        }
    });
}



// POST /api/register
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role = 'employee' } = req.body;
        if (!['employee', 'manager', 'admin'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role' });
        }

        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) return res.status(400).json({ error: 'User with this email already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({ name, email, password: hashedPassword, role });

        const token = jwt.sign({ id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role }, JWT_SECRET, { expiresIn: '24h' });

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role }
        });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(401).json({ error: 'Invalid email or password' });

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) return res.status(401).json({ error: 'Invalid email or password' });

        const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });

        res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role }
        });
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).json({ error: 'Failed to login' });
    }
});

// POST /api/logout 
app.post('/api/logout', (req, res) => {
    res.json({ message: 'Logout successful' });
});


// GET /api/users/profile
app.get('/api/users/profile', requireAuth, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id, { attributes: ['id', 'name', 'email', 'role'] });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
});

// GET /api/users (Admin-only)
app.get('/api/users', requireAdmin, async (req, res) => {
    try {
        const users = await User.findAll({ attributes: ['id', 'name', 'email', 'role'] });
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});


app.get('/api/projects', requireAuth, async (req, res) => {
    try {
        const projects = await Project.findAll({
            include: [{ model: User, as: 'manager', attributes: ['id', 'name', 'email', 'role'] }]
        });
        res.json(projects);
    } catch (error) {
        console.error('Error fetching projects:', error);
        res.status(500).json({ error: 'Failed to fetch projects' });
    }
});

// GET /api/projects/:id
app.get('/api/projects/:id', requireAuth, async (req, res) => {
    try {
        const project = await Project.findByPk(req.params.id, {
            include: [
                { model: User, as: 'manager', attributes: ['id', 'name', 'email', 'role'] },
                { model: Task, include: [{ model: User, as: 'assignedUser', attributes: ['id', 'name', 'email', 'role'] }] }
            ]
        });
        if (!project) return res.status(404).json({ error: 'Project not found' });
        res.json(project);
    } catch (error) {
        console.error('Error fetching project:', error);
        res.status(500).json({ error: 'Failed to fetch project' });
    }
});

// POST /api/projects (Manager + Admin)
app.post('/api/projects', requireManager, async (req, res) => {
    try {
        const { name, description, status = 'active' } = req.body;
        const newProject = await Project.create({ name, description, status, managerId: req.user.id });
        res.status(201).json(newProject);
    } catch (error) {
        console.error('Error creating project:', error);
        res.status(500).json({ error: 'Failed to create project' });
    }
});

// PUT /api/projects/:id (Manager + Admin)
app.put('/api/projects/:id', requireManager, async (req, res) => {
    try {
        const { name, description, status } = req.body;
        const [updatedRowsCount] = await Project.update({ name, description, status }, { where: { id: req.params.id } });
        if (updatedRowsCount === 0) return res.status(404).json({ error: 'Project not found' });
        const updatedProject = await Project.findByPk(req.params.id);
        res.json(updatedProject);
    } catch (error) {
        console.error('Error updating project:', error);
        res.status(500).json({ error: 'Failed to update project' });
    }
});

// DELETE /api/projects/:id (Admin-only)
app.delete('/api/projects/:id', requireAdmin, async (req, res) => {
    try {
        const deletedRowsCount = await Project.destroy({ where: { id: req.params.id } });
        if (deletedRowsCount === 0) return res.status(404).json({ error: 'Project not found' });
        res.json({ message: 'Project deleted successfully' });
    } catch (error) {
        console.error('Error deleting project:', error);
        res.status(500).json({ error: 'Failed to delete project' });
    }
});


// GET /api/projects/:id/tasks
app.get('/api/projects/:id/tasks', requireAuth, async (req, res) => {
    try {
        const tasks = await Task.findAll({
            where: { projectId: req.params.id },
            include: [{ model: User, as: 'assignedUser', attributes: ['id', 'name', 'email', 'role'] }]
        });
        res.json(tasks);
    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    }
});

// POST /api/projects/:id/tasks (Manager + Admin)
app.post('/api/projects/:id/tasks', requireManager, async (req, res) => {
    try {
        const { title, description, assignedUserId, priority = 'medium' } = req.body;
        const newTask = await Task.create({
            title,
            description,
            projectId: req.params.id,
            assignedUserId,
            priority,
            status: 'pending'
        });
        res.status(201).json(newTask);
    } catch (error) {
        console.error('Error creating task:', error);
        res.status(500).json({ error: 'Failed to create task' });
    }
});

// PUT /api/tasks/:id
app.put('/api/tasks/:id', requireAuth, async (req, res) => {
    try {
        const { title, description, status, priority } = req.body;
        const [updatedRowsCount] = await Task.update({ title, description, status, priority }, { where: { id: req.params.id } });
        if (updatedRowsCount === 0) return res.status(404).json({ error: 'Task not found' });
        const updatedTask = await Task.findByPk(req.params.id);
        res.json(updatedTask);
    } catch (error) {
        console.error('Error updating task:', error);
        res.status(500).json({ error: 'Failed to update task' });
    }
});

// DELETE /api/tasks/:id 
app.delete('/api/tasks/:id', requireManager, async (req, res) => {
    try {
        const deletedRowsCount = await Task.destroy({ where: { id: req.params.id } });
        if (deletedRowsCount === 0) return res.status(404).json({ error: 'Task not found' });
        res.json({ message: 'Task deleted successfully' });
    } catch (error) {
        console.error('Error deleting task:', error);
        res.status(500).json({ error: 'Failed to delete task' });
    }
});

// ---------------- Start Server ---------------- //
app.listen(PORT, () => {
    console.log(`Server running on port http://localhost:${PORT}`);
});