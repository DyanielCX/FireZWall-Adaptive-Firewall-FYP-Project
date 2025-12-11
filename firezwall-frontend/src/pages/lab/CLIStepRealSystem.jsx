// ============================================
// CLI Steps in Real-System Page
// Location: /src/pages/lab/CLIStepRealSystem.jsx
// ============================================
import { 
    Server, Terminal, Shield, AlertTriangle, 
    CheckCircle, Lock, Info, ArrowRight, Zap
  } from 'lucide-react';
  import Card from '../../components/ui/Card';
  
  const CLIStepsRealSystem = ({ onNavigate }) => {
    return (
      <div className="space-y-6">
        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-2">
            <div className="bg-gradient-to-br from-green-500 to-emerald-600 p-3 rounded-lg">
              <Terminal className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">Step into Real-System - CLI Configuration</h1>
              <p className="text-slate-400 mt-1">
                Learn how to configure firewall rules using command-line interface in production
              </p>
            </div>
          </div>
        </div>
  
        {/* Important Warning */}
        <Card className="bg-gradient-to-r from-red-500/10 to-orange-500/10 border-red-500/30">
          <div className="flex items-start gap-4">
            <AlertTriangle className="w-6 h-6 text-red-500 flex-shrink-0 mt-1" />
            <div>
              <h3 className="text-xl font-bold text-white mb-2">Before You Begin</h3>
              <p className="text-slate-300 mb-3">
                Configuring firewall rules in a production system requires careful attention. 
                Incorrect configurations can disrupt network access or create security vulnerabilities.
              </p>
              <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                <p className="text-red-400 font-semibold mb-2 flex items-center gap-2">
                  <Info className="w-4 h-4" />
                  Recommended Preparation
                </p>
                <p className="text-slate-300 text-sm">
                  Complete the <button 
                    onClick={() => onNavigate('firewall-learning')}
                    className="text-red-500 hover:text-orange-400 underline font-semibold"
                  >
                    Firewall Rules Learning
                  </button> section first, then practice commands in the <button 
                    onClick={() => onNavigate('cli-practice')}
                    className="text-red-500 hover:text-orange-400 underline font-semibold"
                  >
                    Command Practice
                  </button> environment before working on the actual system.
                </p>
              </div>
            </div>
          </div>
        </Card>
  
        {/* Introduction */}
        <Card>
          <h2 className="text-2xl font-bold text-white mb-4">Two Methods to Configure via CLI</h2>
          <p className="text-slate-300 mb-4">
            There are two primary ways to use CLI commands to configure UFW firewall rules on a server:
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-gradient-to-br from-slate-700/30 to-slate-800/30 rounded-lg p-4 border border-slate-600">
              <div className="flex items-center gap-2 mb-2">
                <Server className="w-5 h-5 text-slate-400" />
                <h3 className="text-lg font-semibold text-white">Method 1: Direct Access</h3>
              </div>
              <p className="text-slate-400 text-sm">Physical access to the server machine</p>
            </div>
            <div className="bg-gradient-to-br from-green-700/30 to-emerald-800/30 rounded-lg p-4 border border-green-600">
              <div className="flex items-center gap-2 mb-2">
                <Lock className="w-5 h-5 text-green-400" />
                <h3 className="text-lg font-semibold text-white">Method 2: SSH Connection</h3>
              </div>
              <p className="text-green-400 text-sm font-semibold">✓ Recommended</p>
            </div>
          </div>
        </Card>
  
        {/* Method 1: Direct Access */}
        <Card className="border-slate-600">
          <div className="flex items-start gap-4 mb-4">
            <div className="bg-slate-700/50 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-slate-300 font-bold text-xl">1</span>
            </div>
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-white mb-2">Method 1: Direct Configuration on Server</h2>
              <p className="text-slate-300">
                This method involves physically accessing the server and running commands directly on the machine's terminal.
              </p>
            </div>
          </div>
  
          {/* Characteristics */}
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-white mb-3">How it Works:</h3>
            <ul className="space-y-2">
              <li className="flex items-start gap-3 text-slate-300">
                <CheckCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <span>Requires physical presence at the server location</span>
              </li>
              <li className="flex items-start gap-3 text-slate-300">
                <CheckCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <span>Access the terminal directly from the server's keyboard and monitor</span>
              </li>
              <li className="flex items-start gap-3 text-slate-300">
                <CheckCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <span>Run UFW commands with root privileges using <code className="text-cyan-400 bg-slate-800 px-2 py-0.5 rounded font-mono text-sm">sudo</code></span>
              </li>
            </ul>
          </div>
  
          {/* Example */}
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-white mb-3">Example Command:</h3>
            <div className="bg-slate-900 rounded-lg p-4 border border-slate-700">
              <code className="text-green-400 text-sm font-mono">sudo ufw status numbered</code>
            </div>
            <div className="mt-2 bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
              <p className="text-sm text-slate-300 flex items-start gap-2">
                <Info className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
                <span>
                  <strong className="text-blue-400">Important:</strong> UFW requires root access to execute. 
                  Always use <code className="text-cyan-400 bg-slate-800 px-1.5 py-0.5 rounded font-mono text-xs">sudo</code> before UFW commands.
                </span>
              </p>
            </div>
          </div>
  
          {/* Why Not Recommended */}
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="text-lg font-semibold text-red-400 mb-2">Why This Method is NOT Recommended</h3>
                <ul className="space-y-1.5 text-sm text-slate-300">
                  <li className="flex items-start gap-2">
                    <span className="text-red-400">•</span>
                    <span>Requires physical access to the server room (security risk)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-400">•</span>
                    <span>No audit trail of who made changes</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-400">•</span>
                    <span>Inconvenient for remote teams or emergency situations</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-400">•</span>
                    <span>No secure session logging</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </Card>
  
        {/* Method 2: SSH Connection */}
        <Card className="border-green-600">
          <div className="flex items-start gap-4 mb-4">
            <div className="bg-green-500/20 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-green-400 font-bold text-xl">2</span>
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-2">
                <h2 className="text-2xl font-bold text-white">Method 2: Connect via SSH Service</h2>
                <span className="px-2 py-1 bg-green-500/20 text-green-400 text-xs font-semibold rounded border border-green-500/30">
                  RECOMMENDED
                </span>
              </div>
              <p className="text-slate-300">
                SSH (Secure Shell) is the industry-standard method for secure remote server administration.
              </p>
            </div>
          </div>
  
          {/* Benefits */}
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-white mb-3">Why SSH is the Best Choice:</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Lock className="w-4 h-4 text-green-400" />
                  <h4 className="font-semibold text-white text-sm">Secure Remote Access</h4>
                </div>
                <p className="text-slate-300 text-sm">Encrypted connection protects commands and data</p>
              </div>
              <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Shield className="w-4 h-4 text-green-400" />
                  <h4 className="font-semibold text-white text-sm">No Physical Access</h4>
                </div>
                <p className="text-slate-300 text-sm">Manage servers from anywhere securely</p>
              </div>
              <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <h4 className="font-semibold text-white text-sm">Activity Monitoring</h4>
                </div>
                <p className="text-slate-300 text-sm">Track and audit all administrative actions</p>
              </div>
              <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Zap className="w-4 h-4 text-green-400" />
                  <h4 className="font-semibold text-white text-sm">Industry Standard</h4>
                </div>
                <p className="text-slate-300 text-sm">Used by professionals worldwide</p>
              </div>
            </div>
          </div>
  
          {/* Standard SSH Connection */}
          <div className="mb-6">
            <h3 className="text-lg font-semibold text-white mb-3">Standard SSH Connection:</h3>
            <div className="bg-slate-900 rounded-lg p-4 border border-slate-700 mb-2">
              <p className="text-slate-400 text-xs mb-2">Basic SSH syntax:</p>
              <code className="text-green-400 text-sm font-mono">ssh &lt;user&gt;@&lt;hostname_or_IP_address&gt;</code>
            </div>
            <p className="text-slate-400 text-sm">
              By default, SSH connects on port 22. However, this configuration is slightlt different in FireZWall...
            </p>
          </div>
  
          {/* FireZWall Specific Configuration */}
          <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4 mb-4">
            <div className="flex items-start gap-3">
              <Info className="w-6 h-6 text-orange-400 flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="text-lg font-semibold text-orange-400 mb-2">FireZWall Special Configuration</h3>
                <p className="text-slate-300 mb-3">
                  FireZWall implements a honeypot system that monitors port 22 to detect potential attackers. 
                  To avoid triggering the honeypot, SSH has been moved to <strong className="text-orange-400">port 2222</strong>.
                </p>
                <div className="bg-slate-900 rounded-lg p-4 border border-slate-700">
                  <p className="text-slate-400 text-xs mb-2">FireZWall SSH connection:</p>
                  <code className="text-green-400 text-sm font-mono">ssh -p 2222 &lt;user&gt;@&lt;hostname_or_IP_address&gt;</code>
                </div>
                <div className="mt-3 bg-slate-800/50 rounded-lg p-3">
                  <p className="text-sm text-slate-300">
                    <strong className="text-orange-400">The <code className="bg-slate-700 px-1.5 py-0.5 rounded font-mono text-xs">-p 2222</code> flag</strong> specifies the custom port number.
                  </p>
                </div>
              </div>
            </div>
          </div>
  
          {/* Connection Example */}
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-white mb-3">Example Connection:</h3>
            <div className="bg-slate-900 rounded-lg p-4 border border-slate-700">
              <div className="space-y-3">
                <div>
                  <p className="text-slate-400 text-xs mb-1">Connect to FireZWall server:</p>
                  <code className="text-green-400 text-sm font-mono">ssh -p 2222 admin@192.168.1.100</code>
                </div>
                <div className="border-t border-slate-700 pt-3">
                  <p className="text-slate-400 text-xs mb-1">Then run UFW commands:</p>
                  <code className="text-green-400 text-sm font-mono">sudo ufw status numbered</code>
                </div>
              </div>
            </div>
          </div>
  
          {/* After Connection */}
          <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
            <h3 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
              <CheckCircle className="w-5 h-5 text-blue-400" />
              After Connecting
            </h3>
            <p className="text-slate-300 mb-3">
              Once connected via SSH, you have full terminal access to the server. 
              You can run any UFW command just as if you were physically at the machine.
            </p>
            <div className="flex items-start gap-2 text-sm text-slate-300">
              <ArrowRight className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
              <span>All firewall commands must be prefixed with <code className="text-cyan-400 bg-slate-800 px-1.5 py-0.5 rounded font-mono text-xs">sudo</code> for root privileges</span>
            </div>
          </div>
        </Card>
  
        {/* Next Steps */}
        <Card className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 border-purple-500/30">
          <div className="text-center py-6">
            <Terminal className="w-12 h-12 text-purple-500 mx-auto mb-3" />
            <h3 className="text-xl font-bold text-white mb-3">Ready to Practice?</h3>
            <p className="text-slate-300 max-w-2xl mx-auto mb-6">
              Now that you understand how to access the system, practice your commands in a safe environment 
              before working on the production server.
            </p>
            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <button
                onClick={() => onNavigate('firewall-learning')}
                className="px-6 py-2.5 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-all flex items-center gap-2 justify-center"
              >
                <Shield className="w-4 h-4" />
                Review Firewall Basics
              </button>
              <button
                onClick={() => onNavigate('cli-practice')}
                className="px-6 py-2.5 bg-gradient-to-r from-purple-500 to-pink-600 hover:from-purple-600 hover:to-pink-700 text-white rounded-lg transition-all flex items-center gap-2 justify-center font-semibold"
              >
                <Terminal className="w-4 h-4" />
                Start Command Practice
              </button>
            </div>
          </div>
        </Card>
      </div>
    );
  };
  
  export default CLIStepsRealSystem;