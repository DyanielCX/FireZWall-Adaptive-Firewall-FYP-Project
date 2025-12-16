// ============================================
// Lab Introduction Page  (Protected)
// Location: /src/pages/lab/LabIntroduction.jsx
// ============================================
import { 
    Shield, BookOpen, Terminal, Code, 
    CheckCircle, Target, Zap, Rocket 
  } from 'lucide-react';
  import Card from '../../components/ui/Card';
  import Button from '../../components/ui/Button';
  
  const LabIntroduction = ({ onNavigate }) => {
    const learningPoints = [
      {
        icon: Shield,
        title: 'Firewall Rules Fundamentals',
        description: 'Master ALLOW, DENY and REJECT actions and understand when to use each'
      },    
      {
        icon: Target,
        title: 'Port & Service Security',
        description: 'Learn to manage ports and services securely in production environments'
      },
      {
        icon: CheckCircle,
        title: 'Security Best Practices',
        description: 'Apply industry-standard configurations and maintain firewall hygiene'
      },
      {
        icon: Code,
        title: 'Firewall Configuration with API',
        description: 'Configure firewall rules programmatically using modern API workflows'
      },
      {
        icon: Terminal,
        title: 'Linux CLI Commands',
        description: 'Mirror API configurations using UFW commands'
      }
    ];
  
    const apiOperations = [
      {
        method: 'POST',
        color: 'text-green-400',
        bg: 'bg-green-500/20',
        border: 'border-green-500/30',
        description: 'Add new firewall rules'
      },
      {
        method: 'GET',
        color: 'text-blue-400',
        bg: 'bg-blue-500/20',
        border: 'border-blue-500/30',
        description: 'View current status and rules'
      },
      {
        method: 'DELETE',
        color: 'text-red-400',
        bg: 'bg-red-500/20',
        border: 'border-red-500/30',
        description: 'Remove existing rules'
      }
    ];
  
    return (
      <div>
        {/* Hero Section */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <div>
              <h1 className="text-3xl font-bold text-white">
                Welcome to the Firewall Configuration Lab
              </h1>
              <p className="text-slate-400 mt-1">
                A hands-on environment to help you learn how to secure networks using real API requests and CLI commands
              </p>
            </div>
          </div>
        </div>
  
        {/* What You Will Learn */}
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
            <Rocket className="w-6 h-6 text-orange-500" />
            What You Will Learn
          </h2>
          <p className="text-slate-300 mb-6 leading-relaxed">
            This practical lab is designed to help students and beginners understand firewall configuration 
            through hands-on experience with both modern APIs and traditional command-line tools.
          </p>
  
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {learningPoints.map((point, index) => (
              <Card key={index} className="hover:border-orange-500/50 transition-all duration-300">
                <div className="flex items-start gap-4">
                  <div className="bg-orange-500/20 p-3 rounded-lg flex-shrink-0">
                    <point.icon className="w-6 h-6 text-orange-500" />
                  </div>
                  <div>
                    <h3 className="text-white font-semibold mb-2">{point.title}</h3>
                    <p className="text-slate-400 text-sm">{point.description}</p>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </div>
  
        {/* Why Use APIs */}
        <div className="mb-8">
          <Card className="bg-gradient-to-br from-slate-800 to-slate-900 border-orange-500/30">
            <div className="flex items-start gap-4 mb-6">
              <div className="bg-orange-500/20 p-3 rounded-lg">
                <Zap className="w-8 h-8 text-orange-500" />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white mb-2">
                  Why Use APIs for Firewall Management?
                </h2>
                <p className="text-slate-300 leading-relaxed">
                  Most modern firewalls (cloud-based, enterprise, microservices) no longer rely solely on GUI 
                  or manual CLI operations. Instead, they expose <span className="text-orange-500 font-semibold">REST APIs for automation </span> 
                  and enabling DevOps teams to integrate security into their CI/CD pipelines to maintain DevSecOps practices.
                </p>
              </div>
            </div>
  
            <div className="bg-slate-800/50 rounded-lg p-6 border border-slate-700">
              <h3 className="text-lg font-semibold text-white mb-4">
                In this lab, you will learn how to configure firewalls using API requests:
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {apiOperations.map((op, index) => (
                  <div 
                    key={index}
                    className={`${op.bg} border ${op.border} rounded-lg p-4 text-center`}
                  >
                    <div className={`text-2xl font-bold ${op.color} mb-2 font-mono`}>
                      {op.method}
                    </div>
                    <p className="text-slate-300 text-sm">{op.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </Card>
        </div>
  
        {/* Call to Action */}
        <Card className="bg-gradient-to-r from-orange-500/10 to-red-600/10 border-orange-500/30">
          <div className="text-center py-8">
            <h2 className="text-2xl font-bold text-white mb-3">
              Ready to Get Started?
            </h2>
            <p className="text-slate-300 mb-6 max-w-2xl mx-auto">
              Whether you're a beginner or sharpening your skills, this lab helps you develop 
              <span className="text-orange-500 font-semibold"> practical, job-ready</span> firewall 
              management experience.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
              <Button
                onClick={() => onNavigate('firewall-learning')}
                className="flex items-center gap-2 px-8"
              >
                <Shield className="w-5 h-5" />
                Start Learning Firewall Rules
              </Button>
              
              <Button
                variant="outline"
                onClick={() => onNavigate('cli-config')}
                className="flex items-center gap-2 px-8"
              >
                <Terminal className="w-5 h-5" />
                Explore CLI Commands
              </Button>
            </div>
          </div>
        </Card>
      </div>
    );
  };
  
  export default LabIntroduction;