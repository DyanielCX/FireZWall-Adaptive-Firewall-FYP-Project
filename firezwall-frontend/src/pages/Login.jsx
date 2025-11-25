// ============================================
// Login Page
// Location: /src/pages/login.js (Next.js) or /src/pages/Login.jsx (React)
// ============================================
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import Input from '../components/ui/Input';
import Alert from '../components/ui/Alert';
import { BASE_URL } from '../api/client';

const Login = () => {
  const navigate = useNavigate();
  const { login } = useAuth();
  
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    // Validate inputs
    if (!username.trim()) {
      setError('Please enter your username');
      return;
    }
    if (!password.trim()) {
      setError('Please enter your password');
      return;
    }
    
    setLoading(true);
    
    try {
      console.log('Attempting login to:', `${BASE_URL}/api/login`);
      await login(username, password);
      console.log('Login successful, redirecting to dashboard...');
      navigate('/dashboard');
    } catch (err) {
      console.error('Login error:', err);
      setError(`Login failed: ${err.message || 'Invalid credentials or server unavailable'}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      <Navbar showLogin={false} />
      
      <main className="flex-1 flex items-center justify-center px-6 py-12">
        <Card className="w-full max-w-md">
          {/* Header */}
          <div className="text-center mb-8">
            <div className="bg-gradient-to-br from-orange-500 to-red-600 w-16 h-16 rounded-xl flex items-center justify-center mx-auto mb-4">
              <Lock className="w-8 h-8 text-white" />
            </div>
            <h2 className="text-2xl font-bold text-white">Welcome Back</h2>
            <p className="text-slate-400 mt-2">
              Sign in to FireZWall Management Console
            </p>
          </div>
          
          {/* Error Alert */}
          {error && (
            <Alert 
              type="error" 
              message={error} 
              onClose={() => setError('')} 
            />
          )}
          
          {/* Login Form */}
          <form onSubmit={handleSubmit} className="space-y-5 mt-6">
            <Input
              label="Username"
              type="text"
              placeholder="Enter your username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
            />
            <Input
              label="Password"
              type="password"
              placeholder="Enter your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
            <Button 
              type="submit"
              className="w-full py-3" 
              disabled={loading}
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>
          
          {/* Back Link */}
          <p className="text-center text-slate-500 text-sm mt-6">
            <button 
              onClick={() => navigate('/')} 
              className="text-orange-500 hover:text-orange-400"
            >
              ← Back to Home
            </button>
          </p>
        </Card>
      </main>
      
      <Footer />
    </div>
  );
};

export default Login;