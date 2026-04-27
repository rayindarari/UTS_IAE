const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { authMiddleware, adminOnly } = require('../middlewares/authMiddleware');

// Public routes
router.post('/register', userController.register);
router.post('/login', userController.login);

// Protected routes (require authentication)
router.get('/profile', authMiddleware, userController.getProfile);
router.post('/change-password/:id', authMiddleware, userController.changePassword);
router.put('/:id', authMiddleware, userController.updateUser);
router.get('/:id', authMiddleware, userController.getUserById);

// Admin only routes
router.get('/', authMiddleware, adminOnly, userController.getAllUsers);
router.delete('/:id', authMiddleware, adminOnly, userController.deleteUser);

module.exports = router;
