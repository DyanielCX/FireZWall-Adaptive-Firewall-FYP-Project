// ============================================
// Lab Dashboard (Lab Practical Section)
// Location: /src/pages/lab/LabDashboard.jsx
// ============================================
import { useState } from 'react';
import { 
  Shield, LogOut, BookOpen, Terminal, Code, 
  FileText, Menu, GraduationCap
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import Card from '../../components/ui/Card';
import LabIntroduction from './LabIntroduction';
import FirewallLearning from './FirewallLearning';


const LabDashboard = ({ onSwitchToRealSystem, username, userRole }) => {
  const { logout } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [activeSection, setActiveSection] = useState('introduction');

  const handleLogout = () => {
    logout();
    window.location.href = '/login';
  };

  const menuItems = [
    { id: 'introduction', icon: BookOpen, label: 'Lab Introduction' },
    { id: 'firewall-learning', icon: Shield, label: 'Firewall Rules Learning' },
    { id: 'api-learning', icon: Code, label: 'API Learning' },
    { 
      id: 'cli-config', 
      icon: Terminal, 
      label: 'CLI-Based Configuration',
      subItems: [
        { id: 'cli-steps', label: 'Steps in Real-System' },
        { id: 'cli-practice', label: 'Command Practice' }
      ]
    },
    { 
      id: 'api-config', 
      icon: Code, 
      label: 'API-Based Configuration',
      subItems: [
        { id: 'api-steps', label: 'Steps in Real-System' },
        { id: 'api-practice', label: 'API Request Practice' }
      ]
    }
  ];

  const getRoleBadgeColor = (role) => {
    switch (role?.toLowerCase()) {
      case 'admin':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'dev':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'cybersec':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
      case 'user':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const renderContent = () => {
    if (activeSection === 'introduction') {
      return <LabIntroduction onNavigate={setActiveSection} />;
    }

    if (activeSection === 'firewall-learning') {
      return <FirewallLearning />;
    }

    // Placeholder for other sections
    return (
      <div className="w-full">
        <h2 className="text-2xl font-bold text-white mb-2">Section Coming Soon</h2>
        <p className="text-slate-400 mb-8">This lab section is under development.</p>
        <Card className="border-dashed border-2 border-slate-600 bg-slate-800/50">
          <div className="text-center py-12">
            <div className="bg-slate-700 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
              <GraduationCap className="w-8 h-8 text-slate-400" />
            </div>
            <h3 className="text-lg font-medium text-slate-300 mb-2">Coming Soon</h3>
            <p className="text-slate-500">This section is under development.</p>
          </div>
        </Card>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-slate-900 flex">
      {/* Sidebar */}
      <aside className={`${sidebarOpen ? 'w-64' : 'w-20'} bg-slate-800 border-r border-slate-700 transition-all duration-300 flex flex-col`}>
        <div className="p-4 border-b border-slate-700 flex items-center gap-3">
          <div className="bg-gradient-to-br from-orange-500 to-red-600 p-2 rounded-lg flex-shrink-0">
            <GraduationCap className="w-5 h-5 text-white" />
          </div>
          {sidebarOpen && (
            <div>
              <span className="font-bold text-white block">FireZWall Lab</span>
              <span className="text-xs text-orange-500">Practical Learning</span>
            </div>
          )}
        </div>
        
        <nav className="flex-1 p-4 overflow-y-auto">
          <ul className="space-y-2">
            {menuItems.map((item) => (
              <li key={item.id}>
                <button
                  onClick={() => setActiveSection(item.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors ${
                    activeSection === item.id 
                      ? 'bg-gradient-to-r from-orange-500/20 to-red-600/20 text-orange-500 border border-orange-500/30' 
                      : 'text-slate-400 hover:bg-slate-700 hover:text-white'
                  }`}
                >
                  <item.icon className="w-5 h-5 flex-shrink-0" />
                  {sidebarOpen && <span className="text-sm">{item.label}</span>}
                </button>
                
                {/* Sub-items */}
                {sidebarOpen && item.subItems && (
                  <ul className="ml-8 mt-1 space-y-1">
                    {item.subItems.map((subItem) => (
                      <li key={subItem.id}>
                        <button
                          onClick={() => setActiveSection(subItem.id)}
                          className={`w-full text-left px-3 py-1.5 rounded text-xs transition-colors ${
                            activeSection === subItem.id
                              ? 'text-orange-500 bg-orange-500/10'
                              : 'text-slate-400 hover:text-white hover:bg-slate-700'
                          }`}
                        >
                          {subItem.label}
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        </nav>
        
        <div className="p-4 border-t border-slate-700">
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-red-400 hover:bg-red-500/10 transition-colors"
          >
            <LogOut className="w-5 h-5 flex-shrink-0" />
            {sidebarOpen && <span>Logout</span>}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Top Bar */}
        <header className="bg-slate-800 border-b border-slate-700 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="text-slate-400 hover:text-white transition-colors"
            >
              <Menu className="w-6 h-6" />
            </button>
            
            {/* Mode Switch Button */}
            <button
              onClick={onSwitchToRealSystem}
              className="px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 hover:text-white transition-all flex items-center gap-2 text-sm border border-slate-600"
            >
              <Shield className="w-4 h-4" />
              <span>Switch to Real System</span>
            </button>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-sm font-medium text-white">{username}</p>
              <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${getRoleBadgeColor(userRole)}`}>
                {userRole}
              </span>
            </div>
            <div className="w-10 h-10 bg-gradient-to-br from-orange-500 to-red-600 rounded-full flex items-center justify-center">
              <span className="text-white font-bold">
                {username.charAt(0).toUpperCase()}
              </span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 p-6 overflow-auto">
          {renderContent()}
        </main>
      </div>
    </div>
  );
};

export default LabDashboard;