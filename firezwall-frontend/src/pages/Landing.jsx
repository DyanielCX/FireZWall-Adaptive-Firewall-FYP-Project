// ============================================
// Landing Page
// Location: /src/pages/index.js (Next.js) or /src/pages/Landing.jsx (React)
// ============================================
import { Shield, Server, FileText, ChevronRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';

const Landing = () => {
  const navigate = useNavigate();

  const features = [
    { 
      icon: Shield, 
      title: 'Firewall Rules', 
      desc: 'Configure and manage network security rules' 
    },
    { 
      icon: Server, 
      title: 'Honeypots', 
      desc: 'Deploy decoys to detect intrusion attempts' 
    },
    { 
      icon: FileText, 
      title: 'System Logs', 
      desc: 'Real-time monitoring and audit trails' 
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      <Navbar />
      
      <main className="flex-1 flex items-center justify-center px-6 py-12">
        <div className="max-w-4xl mx-auto text-center">
          {/* Badge */}
          <div className="mb-8 inline-flex items-center gap-2 bg-orange-500/10 border border-orange-500/30 rounded-full px-4 py-2">
            <Shield className="w-4 h-4 text-orange-500" />
            <span className="text-orange-400 text-sm font-medium">
              Adaptive Security Solution
            </span>
          </div>
          
          {/* Hero Title */}
          <h1 className="text-5xl md:text-6xl font-bold text-white mb-6 leading-tight">
            FireZWall
            <span className="block text-transparent bg-clip-text bg-gradient-to-r from-orange-500 to-red-600">
              Adaptive Firewall Management
            </span>
          </h1>
          
          {/* Description */}
          <p className="text-xl text-slate-300 mb-10 max-w-2xl mx-auto leading-relaxed">
            A practical security learning platform for students and SMEs. 
            Monitor, manage, and protect your network infrastructure with intelligent firewall management.
          </p>
          
          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button 
              onClick={() => navigate('/login')} 
              className="text-lg px-8 py-3"
            >
              Get Started <ChevronRight className="inline w-5 h-5 ml-1" />
            </Button>
            <Button 
              variant="outline" 
              className="text-lg px-8 py-3"
            >
              Learn More
            </Button>
          </div>
          
          {/* Feature Cards */}
          <div className="mt-16 grid grid-cols-1 md:grid-cols-3 gap-6">
            {features.map((feature, index) => (
              <Card key={index} className="text-left">
                <div className="bg-gradient-to-br from-orange-500/20 to-red-600/20 w-12 h-12 rounded-lg flex items-center justify-center mb-4">
                  <feature.icon className="w-6 h-6 text-orange-500" />
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">
                  {feature.title}
                </h3>
                <p className="text-slate-400 text-sm">{feature.desc}</p>
              </Card>
            ))}
          </div>
        </div>
      </main>
      
      <Footer />
    </div>
  );
};

export default Landing;