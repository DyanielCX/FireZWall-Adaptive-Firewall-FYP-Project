// ==================================================
// API Documentation Page
// Location: /src/pages/APIDocs/APIDocumentation.jsx
// ==================================================

import { useState } from 'react';
import { ChevronRight, ChevronDown, Book, Code, Lock, Shield, Server, FileText } from 'lucide-react';
import Navbar from '../../components/Navbar';
import Footer from '../../components/Footer';

import IntroductionContent from './IntroductionDoc';
import LoginEndpointContent from './LoginDoc';
import RefreshTokenEndpointContent from './RefreshTokenDoc';
import LogoutEndpointContent from './LogoutDoc';
import LogoutAllEndpointContent from './LogoutAllDoc';
import ViewUsersEndpointContent from './ViewUserDoc';
import RegisterUsersEndpointContent from './RegisterUserDoc';
import DeleteUsersEndpointContent from './DeleteUserDoc';
import ViewFirewallEndpointContent from './ViewFirewallDoc';
import AddFirewallEndpointContent from './AddFirewallDoc';
import DeleteFirewallEndpointContent from './DeleteFirewallDoc';
import ViewServicePortEndpointContent from './ViewServicePortDoc';
import AddServicePortEndpointContent from './AddServicePortDoc';
import DeleteServicePortEndpointContent from './DeleteServicePortDoc';
import ViewHoneypotEndpointContent from './ViewHoneypotDoc';
import ViewSystemLogsEndpointContent from './ViewSystemLogsDoc';

const APIDocumentation = () => {
  const [activeSection, setActiveSection] = useState('introduction');
  const [expandedModules, setExpandedModules] = useState(['introduction']);
  const [activeTab, setActiveTab] = useState('basic'); // For code samples

  // Scroll to top of the page content
  const handleNavigate = (section) => {
    setActiveSection(section);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Toggle module expansion
  const toggleModule = (moduleId) => {
    setExpandedModules(prev => 
      prev.includes(moduleId) 
        ? prev.filter(id => id !== moduleId)
        : [...prev, moduleId]
    );
  };

  // Navigation structure
  const navigation = [
    {
      id: 'introduction',
      label: 'Introduction',
      icon: Book,
      type: 'single'
    },
    {
      id: 'auth',
      label: 'Authentication',
      icon: Lock,
      type: 'module',
      endpoints: [
        { id: 'auth-login', label: 'Login', method: 'POST' },
        { id: 'auth-refresh', label: 'Refresh Token', method: 'POST' },
        { id: 'auth-logout', label: 'Logout', method: 'POST' },
        { id: 'auth-logout-all', label: 'Logout All Devices', method: 'POST' },
        { id: 'auth-view-user', label: 'View User', method: 'POST' },
        { id: 'auth-register', label: 'Register User', method: 'POST' },
        { id: 'auth-delete', label: 'Delete User', method: 'DELETE' },
      ]
    },
    {
      id: 'firewall',
      label: 'Firewall',
      icon: Shield,
      type: 'module',
      endpoints: [
        { id: 'firewall-view', label: 'View Firewall Rules', method: 'GET' },
        { id: 'firewall-add', label: 'Add Firewall Rule', method: 'POST' },
        { id: 'firewall-delete', label: 'Delete Firewall Rule', method: 'DELETE' },
        { id: 'firewall-port-view', label: 'View Service Ports', method: 'GET' },
        { id: 'firewall-port-add', label: 'Add Service Port', method: 'POST' },
        { id: 'firewall-port-delete', label: 'Delete Service Port', method: 'DELETE' },
      ]
    },
    {
      id: 'honeypot',
      label: 'Honeypot',
      icon: Server,
      type: 'module',
      endpoints: [
        { id: 'honeypot-view', label: 'View Honeypot Reports', method: 'POST' },
      ]
    },
    {
      id: 'syslog',
      label: 'System Logs',
      icon: FileText,
      type: 'module',
      endpoints: [
        { id: 'syslog-view', label: 'View System Logs', method: 'POST' },
      ]
    }
  ];

  // Content for each section
  const getContent = () => {
    switch (activeSection) {
      // Introduction
      case 'introduction':
        return <IntroductionContent />;

      // Auth Module
      case 'auth-login':
        return <LoginEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      case 'auth-refresh':
        return <RefreshTokenEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      case 'auth-logout':
        return <LogoutEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      case 'auth-logout-all':
        return <LogoutAllEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      case 'auth-view-user':
        return <ViewUsersEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      case 'auth-register':
        return <RegisterUsersEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      case 'auth-delete':
        return <DeleteUsersEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;

      // Firewall Module
      case 'firewall-view':
        return <ViewFirewallEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      case 'firewall-add':
        return <AddFirewallEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      case 'firewall-delete':
        return <DeleteFirewallEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      case 'firewall-port-view':
        return <ViewServicePortEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      case 'firewall-port-add':
        return <AddServicePortEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      case 'firewall-port-delete':
        return <DeleteServicePortEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      
      // Honeypot Module
        case 'honeypot-view':
        return <ViewHoneypotEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      
      // System Logs Module
        case 'syslog-view':
        return <ViewSystemLogsEndpointContent activeTab={activeTab} setActiveTab={setActiveTab} />;
      
      default:
        return (
          <div className="bg-slate-800/50 rounded-lg p-8 border border-slate-700/50">
            <h2 className="text-2xl font-bold text-white mb-4">Coming Soon</h2>
            <p className="text-slate-400">
              Documentation for this endpoint is being prepared.
            </p>
          </div>
        );
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      <Navbar />
      
      <main className="flex-1 flex">
        {/* Sidebar Navigation */}
        <aside className="w-80 bg-slate-800/30 backdrop-blur-sm border-r border-slate-700/50 overflow-y-auto">
          <div className="p-6">
            <div className="flex items-center gap-3 mb-6">
              <div className="bg-gradient-to-br from-orange-500 to-red-600 w-10 h-10 rounded-lg flex items-center justify-center">
                <Code className="w-6 h-6 text-white" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-white">API Documentation</h2>
                <p className="text-xs text-slate-400">v1.0</p>
              </div>
            </div>

            <nav className="space-y-1">
              {navigation.map((item) => (
                <div key={item.id}>
                  {item.type === 'single' ? (
                    // Single item (Introduction)
                    <button
                      onClick={() => handleNavigate(item.id)}
                      className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-lg transition-colors ${
                        activeSection === item.id
                          ? 'bg-gradient-to-r from-orange-500 to-red-600 text-white'
                          : 'text-slate-400 hover:bg-slate-700/50 hover:text-white'
                      }`}
                    >
                      <item.icon className="w-5 h-5" />
                      <span className="font-medium">{item.label}</span>
                    </button>
                  ) : (
                    // Module with endpoints
                    <>
                      <button
                        onClick={() => toggleModule(item.id)}
                        className="w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-slate-300 hover:bg-slate-700/50 transition-colors"
                      >
                        <item.icon className="w-5 h-5" />
                        <span className="font-medium flex-1 text-left">{item.label}</span>
                        {expandedModules.includes(item.id) ? (
                          <ChevronDown className="w-4 h-4" />
                        ) : (
                          <ChevronRight className="w-4 h-4" />
                        )}
                      </button>
                      
                      {expandedModules.includes(item.id) && (
                        <div className="ml-2 mt-1 space-y-1 border-l-2 border-slate-700/50 pl-2">
                          {item.endpoints.map((endpoint) => (
                            <button
                              key={endpoint.id}
                              onClick={() => handleNavigate(endpoint.id)}
                              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${
                                activeSection === endpoint.id
                                  ? 'bg-slate-700/50 text-orange-400'
                                  : 'text-slate-400 hover:bg-slate-700/30 hover:text-white'
                              }`}
                            >
                              {/* HTTP Method Badge - Fixed width */}
                              <span className={`text-xs font-mono px-2 py-0.5 rounded font-semibold w-16 text-center ${
                                endpoint.method === 'GET' ? 'bg-blue-500/20 text-blue-400' :
                                endpoint.method === 'POST' ? 'bg-green-500/20 text-green-400' :
                                'bg-red-500/20 text-red-400'
                              }`}>
                                {endpoint.method}
                              </span>
                              
                              {/* Endpoint Label */}
                              <span className="flex-1 text-left">{endpoint.label}</span>
                            </button>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                </div>
              ))}
            </nav>
          </div>
        </aside>

        {/* Main Content */}
        <div className="flex-1 overflow-y-auto">
          <div className="max-w-5xl mx-auto p-8">
            {getContent()}
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default APIDocumentation;