// ============================================
// Firewall Rules Learning Page
// Location: /src/pages/lab/FirewallLearning.jsx
// ============================================
import { useState, useEffect } from 'react';
import { 
  Shield, Terminal, AlertTriangle, CheckCircle, 
  Info, Code, Book, ArrowRight, Lock, Server, X
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import tokenManager from '../../utils/tokenManager';
import apiClient from '../../api/client';
import Card from '../../components/ui/Card';
import Button from '../../components/ui/Button';

const FirewallLearning = () => {
  const { getToken } = useAuth();
  const [activeTab, setActiveTab] = useState('basics');
  const [servicePorts, setServicePorts] = useState([]);
  const [showPortsModal, setShowPortsModal] = useState(false);
  const [loadingPorts, setLoadingPorts] = useState(false);

  const tabs = [
    { id: 'basics', label: 'Rule Basics', icon: Book },
    { id: 'commands', label: 'UFW Commands', icon: Terminal },
    { id: 'order', label: 'Rule Priority', icon: AlertTriangle },
    { id: 'best-practices', label: 'Best Practices', icon: CheckCircle }
  ];

  const fetchServicePorts = async () => {
    setLoadingPorts(true);
    try {
      const token = tokenManager.getAccessToken();
      const response = await apiClient.getServicePorts(token);
      
      if (response.success) {
        setServicePorts(response['service ports'] || []);
      }
    } catch (error) {
      console.error('Error fetching service ports:', error);
    } finally {
      setLoadingPorts(false);
    }
  };

  const handleShowPorts = () => {
    setShowPortsModal(true);
    fetchServicePorts(); // Always fetch when opening modal
  };

  const renderBasics = () => (
    <div className="space-y-6 w-full">
      {/* Introduction */}
      <Card>
        <div className="flex items-start gap-4 mb-4">
          <div className="bg-orange-500/20 p-3 rounded-lg">
            <Shield className="w-6 h-6 text-orange-500" />
          </div>
          <div className="flex-1">
            <h3 className="text-xl font-bold text-white mb-2">Understanding UFW Firewall Rules</h3>
            <p className="text-slate-300">
              UFW (Uncomplicated Firewall) is the firewall tool used by this system. 
              Each rule is built from 5 key elements that control network traffic.
            </p>
          </div>
        </div>
      </Card>

      {/* Action */}
      <Card>
        <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <div className="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center">
            <span className="text-blue-400 font-bold">1</span>
          </div>
          Action
        </h4>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-slate-700/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded text-xs font-mono bg-green-500/20 text-green-400">allow</span>
              <span className="text-slate-400 text-sm">Permits traffic</span>
            </div>
          </div>
          <div className="bg-slate-700/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded text-xs font-mono bg-red-500/20 text-red-400">deny</span>
              <span className="text-slate-400 text-sm">Blocks traffic silently</span>
            </div>
          </div>
          <div className="bg-slate-700/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded text-xs font-mono bg-orange-500/20 text-orange-400">reject</span>
              <span className="text-slate-400 text-sm">Blocks + sends rejection message</span>
            </div>
          </div>
          <div className="bg-slate-700/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded text-xs font-mono bg-purple-500/20 text-purple-400">delete</span>
              <span className="text-slate-400 text-sm">Removes a rule by number</span>
            </div>
          </div>
        </div>
      </Card>

      {/* Port */}
      <Card>
        <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <div className="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center">
            <span className="text-blue-400 font-bold">2</span>
          </div>
          Port
        </h4>
        <p className="text-slate-300 text-sm mb-4">
          Specify which port number to open or restrict.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div className="bg-slate-700/30 rounded-lg p-3">
            <div className="flex items-center justify-between mb-1">
              <span className="text-white font-medium text-sm">Well-Known Ports</span>
              <span className="text-slate-400 text-xs font-mono">0-1023</span>
            </div>
            <p className="text-slate-400 text-xs">System-level services (SSH, HTTP, HTTPS)</p>
          </div>
          <div className="bg-slate-700/30 rounded-lg p-3">
            <div className="flex items-center justify-between mb-1">
              <span className="text-white font-medium text-sm">Registered Ports</span>
              <span className="text-slate-400 text-xs font-mono">1024-49151</span>
            </div>
            <p className="text-slate-400 text-xs">Specific applications & services</p>
          </div>
          <div className="bg-slate-700/30 rounded-lg p-3">
            <div className="flex items-center justify-between mb-1">
              <span className="text-white font-medium text-sm">Dynamic Ports</span>
              <span className="text-slate-400 text-xs font-mono">49152-65535</span>
            </div>
            <p className="text-slate-400 text-xs">Temporary outgoing connections</p>
          </div>
        </div>
        <Button
          variant="outline"
          onClick={handleShowPorts}
          className="w-full md:w-auto text-sm flex items-center justify-center gap-2"
        >
          <Server className="w-4 h-4" />
          View Common Service Ports
        </Button>
      </Card>

      {/* Protocol */}
      <Card>
        <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <div className="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center">
            <span className="text-blue-400 font-bold">3</span>
          </div>
          Protocol
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-slate-700/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-0.5 rounded text-xs font-mono bg-green-500/20 text-green-400">TCP</span>
              <span className="text-white font-medium text-sm">Transmission Control Protocol</span>
            </div>
            <p className="text-slate-400 text-sm mb-2">
              Reliable and connection-oriented. Ensures all data arrives in order with error-checking.
            </p>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <CheckCircle className="w-3 h-3 text-green-400" />
              <span>Reliable delivery</span>
              <CheckCircle className="w-3 h-3 text-green-400" />
              <span>Error checking</span>
            </div>
            <p className="text-slate-500 text-xs mt-2">
              ⚡ Slower due to overhead, but guarantees delivery
            </p>
          </div>
          
          <div className="bg-slate-700/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-0.5 rounded text-xs font-mono bg-purple-500/20 text-purple-400">UDP</span>
              <span className="text-white font-medium text-sm">User Datagram Protocol</span>
            </div>
            <p className="text-slate-400 text-sm mb-2">
              Fast and connectionless. Sends data with minimal overhead but no delivery guarantees (best-effort).
            </p>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <CheckCircle className="w-3 h-3 text-purple-400" />
              <span>High speed</span>
              <CheckCircle className="w-3 h-3 text-purple-400" />
              <span>Low latency</span>
            </div>
            <p className="text-slate-500 text-xs mt-2">
              ⚡ Ideal for streaming, gaming, and real-time apps
            </p>
          </div>
        </div>
      </Card>

      {/* Direction */}
      <Card>
        <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <div className="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center">
            <span className="text-blue-400 font-bold">4</span>
          </div>
          Direction
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-slate-700/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-0.5 rounded text-xs font-mono bg-blue-500/20 text-blue-400">in</span>
              <span className="text-white font-medium">Incoming Traffic</span>
            </div>
            <p className="text-slate-400 text-sm">
              Monitors traffic coming INTO your system from external sources
            </p>
          </div>
          
          <div className="bg-slate-700/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-0.5 rounded text-xs font-mono bg-purple-500/20 text-purple-400">out</span>
              <span className="text-white font-medium">Outgoing Traffic</span>
            </div>
            <p className="text-slate-400 text-sm">
              Monitors traffic going OUT from your system to external destinations
            </p>
          </div>
        </div>
      </Card>

      {/* Source */}
      <Card>
        <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <div className="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center">
            <span className="text-blue-400 font-bold">5</span>
          </div>
          Source Address
        </h4>
        <p className="text-slate-300 text-sm mb-4">
          Specify which IP address or subnet the rule applies to.
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-slate-700/30 rounded-lg p-3">
            <span className="text-white font-medium text-sm">IPv4 Address</span>
            <p className="text-slate-400 text-xs font-mono mt-1">Example: 192.168.1.10</p>
          </div>
          <div className="bg-slate-700/30 rounded-lg p-3">
            <span className="text-white font-medium text-sm">IPv4 Subnet</span>
            <p className="text-slate-400 text-xs font-mono mt-1">Example: 192.168.1.0/24</p>
          </div>
          <div className="bg-slate-700/30 rounded-lg p-3">
            <span className="text-white font-medium text-sm">IPv6 Address</span>
            <p className="text-slate-400 text-xs font-mono mt-1">Example: 2001:db8::1</p>
          </div>
          <div className="bg-slate-700/30 rounded-lg p-3">
            <span className="text-white font-medium text-sm">IPv6 Subnet</span>
            <p className="text-slate-400 text-xs font-mono mt-1">Example: 2001:db8::/32</p>
          </div>
        </div>
      </Card>
    </div>
  );

  const renderCommands = () => (
    <div className="space-y-6 w-full">
      {/* View Rules */}
      <Card>
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <Terminal className="w-6 h-6 text-orange-500" />
          View Firewall Rules
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
            <p className="text-slate-400 text-sm mb-2">View all active rules:</p>
            <code className="text-green-400 font-mono text-sm">sudo ufw status</code>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
            <p className="text-slate-400 text-sm mb-2">View rules with numbers (for deletion):</p>
            <code className="text-green-400 font-mono text-sm">sudo ufw status numbered</code>
          </div>
        </div>
      </Card>

      {/* Add Rules */}
      <Card>
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <Code className="w-6 h-6 text-orange-500" />
          Add Firewall Rules
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <h4 className="text-white font-semibold mb-2 text-sm">Basic Rule (Port + Protocol)</h4>
            <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
              <code className="text-green-400 font-mono text-sm">
                sudo ufw &lt;action&gt; &lt;port&gt;/&lt;protocol&gt;
              </code>
              <p className="text-slate-400 text-xs mt-2">Example: <code className="text-orange-400">sudo ufw allow 22/tcp</code></p>
            </div>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-2 text-sm">With Direction</h4>
            <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
              <code className="text-green-400 font-mono text-sm">
                sudo ufw &lt;action&gt; &lt;direction&gt; &lt;port&gt;/&lt;protocol&gt;
              </code>
              <p className="text-slate-400 text-xs mt-2">Example: <code className="text-orange-400">sudo ufw deny in 22/tcp</code></p>
            </div>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-2 text-sm">With Source Address</h4>
            <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
              <code className="text-green-400 font-mono text-sm">
                sudo ufw &lt;action&gt; from &lt;source&gt; to any port &lt;port&gt; proto &lt;protocol&gt;
              </code>
              <p className="text-slate-400 text-xs mt-2">Example: <code className="text-orange-400">sudo ufw allow from 192.168.1.100 to any port 22 proto tcp</code></p>
            </div>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-2 text-sm">With Direction & Source Address</h4>
            <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
              <code className="text-green-400 font-mono text-sm">
                sudo ufw &lt;action&gt; &lt;direction&gt; from &lt;source&gt; to any port &lt;port&gt; proto &lt;protocol&gt;
              </code>
              <p className="text-slate-400 text-xs mt-2">Example: <code className="text-orange-400">sudo ufw allow in from 192.168.1.100 to any port 22 proto tcp</code></p>
            </div>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-2 text-sm">Insert at Specific Position</h4>
            <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
              <code className="text-green-400 font-mono text-sm">
                sudo ufw insert &lt;rule_num&gt; &lt;action&gt; &lt;port&gt;/&lt;protocol&gt;
              </code>
              <p className="text-slate-400 text-xs mt-2">Example: <code className="text-orange-400">sudo ufw insert 1 deny 80/tcp</code></p>
            </div>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-2 text-sm">Insert at Specific Position with Direction</h4>
            <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
              <code className="text-green-400 font-mono text-sm">
                sudo ufw insert &lt;rule_num&gt; &lt;action&gt; &lt;direction&gt; &lt;port&gt;/&lt;protocol&gt;
              </code>
              <p className="text-slate-400 text-xs mt-2">Example: <code className="text-orange-400">sudo ufw insert 1 deny in 80/tcp</code></p>
            </div>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-2 text-sm">Insert at Specific Position with Source</h4>
            <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
              <code className="text-green-400 font-mono text-sm">
                sudo ufw insert &lt;rule_num&gt; &lt;action&gt; from &lt;source&gt; to any port &lt;port&gt; proto &lt;protocol&gt;
              </code>
              <p className="text-slate-400 text-xs mt-2">Example: <code className="text-orange-400">sudo ufw insert 1 deny from 192.168.1.100 to any port 80 proto tcp</code></p>
            </div>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-2 text-sm">Insert at Specific Position with Direction & Source</h4>
            <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
              <code className="text-green-400 font-mono text-sm">
                sudo ufw insert &lt;rule_num&gt; &lt;action&gt; &lt;direction&gt; from &lt;source&gt; to any port &lt;port&gt; proto &lt;protocol&gt;
              </code>
              <p className="text-slate-400 text-xs mt-2">Example: <code className="text-orange-400">sudo ufw insert 1 deny in from 192.168.1.100 to any port 80 proto tcp</code></p>
            </div>
          </div>
        </div>
      </Card>

      {/* Delete Rules */}
      <Card>
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <AlertTriangle className="w-6 h-6 text-red-500" />
          Delete Firewall Rules
        </h3>
        <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
          <code className="text-green-400 font-mono text-sm">
            sudo ufw delete &lt;rule_num&gt;
          </code>
          <p className="text-slate-400 text-xs mt-2">Example: <code className="text-orange-400">sudo ufw delete 3</code></p>
          <div className="mt-3 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
            <p className="text-red-400 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Always check rule numbers with <code className="text-red-300">sudo ufw status numbered</code> before deleting!
            </p>
          </div>
        </div>
      </Card>
    </div>
  );

  const renderOrder = () => (
    <div className="space-y-6 w-full">
      {/* Introduction */}
      <Card className="bg-gradient-to-r from-orange-500/10 to-red-600/10 border-orange-500/30">
        <div className="flex items-start gap-4">
          <div className="bg-orange-500/20 p-3 rounded-lg">
            <AlertTriangle className="w-8 h-8 text-orange-500" />
          </div>
          <div>
            <h3 className="text-xl font-bold text-white mb-2">Rule Order Matters!</h3>
            <p className="text-slate-300 leading-relaxed">
              UFW processes firewall rules <span className="text-orange-500 font-semibold">from top to bottom</span> based 
              on rule numbers. Once a rule matches, UFW stops checking. This means rule position directly affects whether 
              traffic is allowed or denied.
            </p>
          </div>
        </div>
      </Card>

      {/* Why It Matters */}
      <Card>
        <h3 className="text-lg font-bold text-white mb-4">Why Rule Order Matters</h3>
        <div className="space-y-3">
          {[
            { icon: Lock, text: 'UFW stops checking once a rule matches', color: 'blue' },
            { icon: ArrowRight, text: 'Specific rules should be placed above general rules', color: 'purple' },
            { icon: Shield, text: 'DENY rules need priority to prevent bypass', color: 'red' },
            { icon: AlertTriangle, text: 'Misordered rules create security gaps', color: 'orange' }
          ].map((item, index) => (
            <div key={index} className="flex items-center gap-3 p-3 bg-slate-700/30 rounded-lg">
              <div className={`bg-${item.color}-500/20 p-2 rounded-lg`}>
                <item.icon className={`w-5 h-5 text-${item.color}-400`} />
              </div>
              <span className="text-slate-300 text-sm">{item.text}</span>
            </div>
          ))}
        </div>
      </Card>

      {/* Bad Example */}
      <Card className="border-red-500/30 bg-red-500/5">
        <div className="flex items-center gap-2 mb-4">
          <div className="bg-red-500/20 p-2 rounded-lg">
            <AlertTriangle className="w-6 h-6 text-red-400" />
          </div>
          <h3 className="text-lg font-bold text-white">❌ Wrong Configuration (Security Risk)</h3>
        </div>
        <p className="text-slate-300 mb-4 text-sm">
          Placing a general ALLOW rule above a specific DENY rule creates a security vulnerability:
        </p>
        <div className="bg-slate-900/50 rounded-lg p-4 border border-red-500/30 font-mono text-sm">
          <div className="grid grid-cols-3 gap-4 text-slate-400 mb-2">
            <span>To</span>
            <span>Action</span>
            <span>From</span>
          </div>
          <div className="grid grid-cols-3 gap-4 text-red-400">
            <span>[1] 22/tcp</span>
            <span>ALLOW IN</span>
            <span>Anywhere</span>
          </div>
          <div className="grid grid-cols-3 gap-4 text-slate-500 mt-1">
            <span>[2] Anywhere</span>
            <span>DENY IN</span>
            <span>192.168.253.140</span>
          </div>
        </div>
        <div className="mt-4 p-3 bg-red-500/10 rounded-lg">
          <p className="text-red-400 text-sm">
            ⚠️ <strong>Problem:</strong> The attacker at <code>192.168.253.140</code> can still reach port 22 
            because Rule [1] matches first!
          </p>
        </div>
      </Card>

      {/* Good Example */}
      <Card className="border-green-500/30 bg-green-500/5">
        <div className="flex items-center gap-2 mb-4">
          <div className="bg-green-500/20 p-2 rounded-lg">
            <CheckCircle className="w-6 h-6 text-green-400" />
          </div>
          <h3 className="text-lg font-bold text-white">Correct Configuration (Secure)</h3>
        </div>
        <p className="text-slate-300 mb-4 text-sm">
          Place specific DENY rules before general ALLOW rules:
        </p>
        <div className="bg-slate-900/50 rounded-lg p-4 border border-green-500/30 font-mono text-sm">
          <div className="grid grid-cols-3 gap-4 text-slate-400 mb-2">
            <span>To</span>
            <span>Action</span>
            <span>From</span>
          </div>
          <div className="grid grid-cols-3 gap-4 text-red-400">
            <span>[1] Anywhere</span>
            <span>DENY IN</span>
            <span>192.168.253.140</span>
          </div>
          <div className="grid grid-cols-3 gap-4 text-green-400 mt-1">
            <span>[2] 22/tcp</span>
            <span>ALLOW IN</span>
            <span>Anywhere</span>
          </div>
        </div>
        <div className="mt-4 p-3 bg-green-500/10 rounded-lg">
          <p className="text-green-400 text-sm">
            ✅ <strong>Secure:</strong> Traffic from <code>192.168.253.140</code> is blocked by Rule [1] 
            before Rule [2] can allow it!
          </p>
        </div>
      </Card>
    </div>
  );

  const renderBestPractices = () => (
    <div className="space-y-6 w-full">
      <Card>
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <CheckCircle className="w-6 h-6 text-green-500" />
          Best Practices for UFW Configuration
        </h3>
        <p className="text-slate-300 mb-6">
          Follow these guidelines to maintain a secure and effective firewall configuration:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[
            {
              title: 'Start with Default Deny',
              desc: 'Block all incoming traffic by default, only allow what\'s necessary',
              commands: ['ufw default deny incoming', 'ufw default allow outgoing'],
              icon: Shield,
              color: 'red'
            },
            {
              title: 'Allow Only Necessary Ports',
              desc: 'Only open ports for services you actually use (SSH, web servers, etc.)',
              commands: ['ufw allow 22/tcp', 'ufw allow 80/tcp', 'ufw allow 443/tcp'],
              icon: Lock,
              color: 'blue'
            },
            {
              title: 'Prioritize DENY Rules',
              desc: 'Place specific DENY rules at the top using insert command',
              commands: ['ufw insert 1 deny from 192.168.1.100'],
              icon: AlertTriangle,
              color: 'orange'
            },
            {
              title: 'Avoid Broad Rules',
              desc: 'Don\'t use "ALLOW ANYWHERE" unless absolutely necessary',
              tip: 'Be specific with source addresses and ports',
              icon: Info,
              color: 'yellow'
            },
            {
              title: 'Enable Logging',
              desc: 'Monitor traffic and detect suspicious activity',
              commands: ['ufw logging on'],
              icon: Terminal,
              color: 'purple'
            },
            {
              title: 'Regular Review',
              desc: 'Check your rules periodically and remove outdated ones',
              commands: ['ufw status numbered'],
              icon: CheckCircle,
              color: 'green'
            },
            {
              title: 'Reload After Changes',
              desc: 'Apply large changes cleanly by reloading UFW',
              commands: ['ufw reload'],
              icon: Code,
              color: 'cyan'
            }
          ].map((practice, index) => (
            <Card key={index} className="bg-slate-700/30">
              <div className="flex items-start gap-4">
                <div className={`bg-${practice.color}-500/20 p-3 rounded-lg flex-shrink-0`}>
                  <practice.icon className={`w-6 h-6 text-${practice.color}-400`} />
                </div>
                <div className="flex-1">
                  <h4 className="text-white font-semibold mb-2">{practice.title}</h4>
                  <p className="text-slate-400 text-sm mb-3">{practice.desc}</p>
                  {practice.commands && (
                    <div className="bg-slate-900/50 rounded-lg p-3 border border-slate-600">
                      {practice.commands.map((cmd, i) => (
                        <code key={i} className="text-green-400 font-mono text-xs block">
                          {cmd}
                        </code>
                      ))}
                    </div>
                  )}
                  {practice.tip && (
                    <p className="text-slate-500 text-xs mt-2 italic">💡 {practice.tip}</p>
                  )}
                </div>
              </div>
            </Card>
          ))}
        </div>
      </Card>

      {/* Quick Checklist */}
      <Card className="bg-gradient-to-r from-green-500/10 to-emerald-600/10 border-green-500/30">
        <h3 className="text-lg font-bold text-white mb-4">✅ Security Checklist</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            'Default deny incoming traffic',
            'Allow only necessary ports',
            'DENY rules are at the top',
            'No broad ALLOW rules',
            'Logging is enabled',
            'Rules reviewed regularly',
            'Unused rules removed',
            'Configuration tested'
          ].map((item, index) => (
            <div key={index} className="flex items-center gap-2 text-sm text-slate-300">
              <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
              <span>{item}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );

  return (
    <div className="w-full">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <div className="bg-gradient-to-br from-orange-500 to-red-600 p-3 rounded-lg">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white">Firewall Rules Learning</h1>
            <p className="text-slate-400 mt-1">
            Master UFW firewall configuration with hands-on examples and best practices
            </p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6">
        <div className="flex flex-wrap gap-2">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg font-medium transition-all ${
                activeTab === tab.id
                  ? 'bg-gradient-to-r from-orange-500 to-red-600 text-white'
                  : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      {activeTab === 'basics' && renderBasics()}
      {activeTab === 'commands' && renderCommands()}
      {activeTab === 'order' && renderOrder()}
      {activeTab === 'best-practices' && renderBestPractices()}

      {/* Service Ports Modal */}
      {showPortsModal && (
        <div 
          className="fixed inset-0 bg-black/70 flex items-start justify-center z-50 p-4 overflow-y-auto"
          onClick={() => setShowPortsModal(false)}
        >
          <style>{`
            .custom-scrollbar::-webkit-scrollbar {
              width: 8px;
            }
            .custom-scrollbar::-webkit-scrollbar-track {
              background: transparent;
            }
            .custom-scrollbar::-webkit-scrollbar-thumb {
              background-color: rgba(148, 163, 184, 0.3);
              border-radius: 4px;
            }
            .custom-scrollbar::-webkit-scrollbar-thumb:hover {
              background-color: rgba(148, 163, 184, 0.5);
            }
          `}</style>
          <Card 
            className="w-full max-w-2xl max-h-[80vh] overflow-y-auto custom-scrollbar pt-8"
            onClick={(e) => e.stopPropagation()}
            style={{
              scrollbarWidth: 'thin',
              scrollbarColor: 'rgba(148, 163, 184, 0.3) transparent'
            }}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold text-white">Common Service Ports</h3>
              <button
                onClick={() => setShowPortsModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {loadingPorts ? (
              <div className="text-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500 mx-auto"></div>
                <p className="text-slate-400 mt-3">Loading service ports...</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-slate-700">
                      <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">Service</th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">Port</th>
                    </tr>
                  </thead>
                  <tbody>
                    {servicePorts.map((item, index) => (
                      <tr key={index} className="border-b border-slate-700/50">
                        <td className="py-3 px-4 text-slate-300">{item.service}</td>
                        <td className="py-3 px-4 text-orange-400 font-mono">{item.port}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  );
};

export default FirewallLearning;