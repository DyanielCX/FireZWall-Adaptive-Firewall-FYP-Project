// Navbar Component
import { Shield } from 'lucide-react';
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

        {/* Login Button */}
        {showLogin && (
          <Button onClick={() => navigate('/login')}>
            Login
          </Button>
        )}
      </div>
    </nav>
  );
};

export default Navbar;