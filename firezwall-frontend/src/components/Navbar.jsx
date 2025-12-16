// ============================================
// Navbar Component
// Location: /src/components/Navbar.jsx
// ============================================
import { Shield, BookOpen } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import Button from './ui/Button';

const Navbar = ({ showLogin = true }) => {
  const navigate = useNavigate();

  return (
    <nav className="bg-slate-900 border-b border-slate-700 px-6 py-4">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Logo */}
        <div 
          className="flex items-center gap-3 cursor-pointer"
          onClick={() => navigate('/')}
        >
          <div className="bg-gradient-to-br from-orange-500 to-red-600 p-2 rounded-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <span className="text-xl font-bold text-white">FireZWall</span>
        </div>

        {/* Right Side - API Docs + Login */}
        <div className="flex items-center gap-4">
          {/* API Documentation Link */}
          <button
            onClick={() => navigate('/api-docs')}
            className="flex items-center gap-2 text-slate-300 hover:text-white transition-colors"
          >
            <BookOpen className="w-5 h-5" />
            <span className="hidden sm:inline">API Docs</span>
          </button>

          {/* Login Button */}
          {showLogin && (
            <Button onClick={() => navigate('/login')}>
              Login
            </Button>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;