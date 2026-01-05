// ============================================
// CLI Command Practice Page
// Location: /src/pages/lab/CLICommandPractice.jsx
// ============================================

import { useState } from 'react';
import { 
  Terminal, CheckCircle, XCircle, 
  Info, RotateCcw, Lightbulb, Shield, Sparkles, 
  BookOpen, Zap
} from 'lucide-react';
import Card from '../../components/ui/Card';
import Button from '../../components/ui/Button';
import Input from '../../components/ui/Input';

const CLICommandPractice = () => {
  // Configuration state
  const [config, setConfig] = useState({
    action: 'allow',
    port: '',
    protocol: 'tcp',
    direction: '', // Optional - empty string means no direction
    source: '',
    ruleType: 'normal', // 'normal' or 'insert'
    ruleNumber: ''
  });

  // Command input state
  const [userCommand, setUserCommand] = useState('');
  const [result, setResult] = useState(null); // { correct: boolean, message: string, expectedCommand: string, showAnswer: boolean }
  const [attemptsLeft, setAttemptsLeft] = useState(5); // Changed to attempts left
  const [maxAttempts] = useState(5);
  const [showExamples, setShowExamples] = useState(false);
  const [difficulty, setDifficulty] = useState('easy'); // 'easy', 'medium', 'hard'
  const [hintsUsed, setHintsUsed] = useState(0);
  const [showHint, setShowHint] = useState(false);

  // Validate IP address or subnet (IPv4 and IPv6)
  const validateIPAddress = (ip) => {
    if (!ip) return true; // Empty is valid (optional field)
    
    // IPv4 with CIDR notation (e.g., 192.168.1.0/24)
    const ipv4CidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    if (ipv4CidrRegex.test(ip)) {
      const [address, mask] = ip.split('/');
      const octets = address.split('.').map(Number);
      const maskNum = parseInt(mask);
      return octets.every(octet => octet >= 0 && octet <= 255) && maskNum >= 0 && maskNum <= 32;
    }
    
    // IPv4 regular address (e.g., 192.168.1.100)
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(ip)) {
      const octets = ip.split('.').map(Number);
      return octets.every(octet => octet >= 0 && octet <= 255);
    }

    // IPv6 with CIDR notation (e.g., 2001:db8::/32)
    const ipv6CidrRegex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\/\d{1,3}$/;
    if (ipv6CidrRegex.test(ip)) {
      const maskNum = parseInt(ip.split('/')[1]);
      return maskNum >= 0 && maskNum <= 128;
    }
    
    // IPv6 regular address (e.g., 2001:db8::1, ::1, fe80::1)
    const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
    if (ipv6Regex.test(ip)) {
      return true;
    }

    // IPv6 shortened format (e.g., ::1, ::)
    const ipv6ShortRegex = /^::([0-9a-fA-F]{0,4}:){0,6}[0-9a-fA-F]{0,4}$|^([0-9a-fA-F]{0,4}:){1,7}:$/;
    if (ipv6ShortRegex.test(ip)) {
      return true;
    }
    
    return false;
  };

  // Generate expected command based on configuration
  const generateExpectedCommand = () => {
    let command = 'sudo ufw';

    // Handle insert
    if (config.ruleType === 'insert' && config.ruleNumber) {
      command += ` insert ${config.ruleNumber}`;
    }

    // Add action
    command += ` ${config.action}`;

    // Add direction (optional)
    if (config.direction) {
      command += ` ${config.direction}`;
    }

    // Handle source - different syntax when source is provided
    if (config.source) {
      command += ` from ${config.source} to any port ${config.port} proto ${config.protocol}`;
    } else {
      // Simple format without source
      command += ` ${config.port}/${config.protocol}`;
    }

    return command;
  };

  // Validate user command
  const handleCheckCommand = () => {
    const expectedCommand = generateExpectedCommand();
    const userCommandTrimmed = userCommand.trim().toLowerCase();
    const expectedCommandLower = expectedCommand.toLowerCase();

    const newAttemptsLeft = attemptsLeft - 1;
    setAttemptsLeft(newAttemptsLeft);

    if (userCommandTrimmed === expectedCommandLower) {
      setResult({
        correct: true,
        message: 'Perfect! Your command is correct! 🎉',
        expectedCommand: expectedCommand,
        showAnswer: true
      });
    } else {
      // Only show answer if no attempts left
      const showAnswer = newAttemptsLeft === 0;
      setResult({
        correct: false,
        message: showAnswer 
          ? 'Out of attempts! Here\'s the correct answer:' 
          : `Incorrect. You have ${newAttemptsLeft} attempt${newAttemptsLeft !== 1 ? 's' : ''} remaining.`,
        expectedCommand: expectedCommand,
        showAnswer: showAnswer
      });
    }
  };

  // Reset all fields
  const handleReset = () => {
    setConfig({
      action: 'allow',
      port: '',
      protocol: 'tcp',
      direction: '',
      source: '',
      ruleType: 'normal',
      ruleNumber: ''
    });
    setUserCommand('');
    setResult(null);
    setShowHint(false);
    setAttemptsLeft(maxAttempts); // Reset attempts
    setHintsUsed(0); // Reset hints
  };

  // Try another command (after success or failure)
  const handleTryAnother = () => {
    setConfig({
      action: 'allow',
      port: '',
      protocol: 'tcp',
      direction: '',
      source: '',
      ruleType: 'normal',
      ruleNumber: ''
    });
    setUserCommand('');
    setResult(null);
    setShowHint(false);
    setAttemptsLeft(maxAttempts); // Reset attempts
    setHintsUsed(0); // Reset hints
  };

  // Quick fill with random values based on difficulty
  const handleQuickFill = () => {
    const actions = ['allow', 'deny', 'reject'];
    const protocols = ['tcp', 'udp'];
    const directions = ['', 'in', 'out'];
    const commonPorts = {
      easy: [22, 80, 443, 3306, 5432],
      medium: [8080, 3000, 5000, 27017, 6379],
      hard: [2222, 8443, 9090, 15672, 50000]
    };
    
    const port = commonPorts[difficulty][Math.floor(Math.random() * commonPorts[difficulty].length)];
    const action = actions[Math.floor(Math.random() * actions.length)];
    const protocol = protocols[Math.floor(Math.random() * protocols.length)];
    
    let newConfig = {
      action,
      port: port.toString(),
      protocol,
      direction: difficulty === 'easy' ? '' : directions[Math.floor(Math.random() * directions.length)],
      source: '',
      ruleType: 'normal',
      ruleNumber: ''
    };

    // Add source for medium/hard
    if (difficulty === 'medium' && Math.random() > 0.5) {
      newConfig.source = '192.168.1.100';
    } else if (difficulty === 'hard') {
      newConfig.source = Math.random() > 0.5 ? '192.168.1.0/24' : '10.0.0.50';
      newConfig.ruleType = Math.random() > 0.5 ? 'insert' : 'normal';
      if (newConfig.ruleType === 'insert') {
        newConfig.ruleNumber = Math.floor(Math.random() * 5 + 1).toString();
      }
    }

    setConfig(newConfig);
    setUserCommand('');
    setResult(null);
    setShowHint(false);
  };

  // Show progressive hints
  const handleShowHint = () => {
    setShowHint(true);
    setHintsUsed(hintsUsed + 1);
  };

  // Generate hint based on configuration
  const generateHint = () => {
    if (hintsUsed === 0) {
      return "Remember: All UFW commands start with 'sudo ufw'";
    } else if (hintsUsed === 1) {
      if (config.source) {
        return "When using a source IP, the format is: from <source> to any port <port> proto <protocol>";
      } else {
        return "For simple rules, use the format: <port>/<protocol>";
      }
    } else if (hintsUsed === 2) {
      if (config.ruleType === 'insert') {
        return `Don't forget to include 'insert ${config.ruleNumber}' before the action`;
      } else {
        return `The order is: sudo ufw ${config.direction ? '[direction]' : ''} [action] ...`;
      }
    } else {
      return `Here's the structure: sudo ufw ${config.ruleType === 'insert' ? `insert ${config.ruleNumber}` : ''} ${config.action} ${config.direction || ''}...`;
    }
  };

  // Check if form is complete enough to submit
  const isFormValid = () => {
    if (!config.port) return false;
    if (config.ruleType === 'insert' && !config.ruleNumber) return false;
    if (config.source && !validateIPAddress(config.source)) return false;
    return true;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <div className="bg-gradient-to-br from-purple-500 to-pink-600 p-3 rounded-lg">
            <Terminal className="w-8 h-8 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white">Command Practice</h1>
            <p className="text-slate-400 mt-1">
              Practice your UFW firewall commands skill in a safe environment
            </p>
          </div>
        </div>
      </div>

      {/* Introduction */}
      <Card className="bg-gradient-to-r from-blue-500/10 to-cyan-500/10 border-blue-500/30">
        <div className="flex items-start gap-4">
          <Info className="w-6 h-6 text-blue-400 flex-shrink-0 mt-1" />
          <div>
            <h3 className="text-lg font-bold text-white mb-2">How This Works</h3>
            <ol className="space-y-2 text-slate-300">
              <li className="flex items-start gap-2">
                <span className="text-blue-400 font-semibold">1.</span>
                <span>Configure your desired firewall rule using the options below</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-400 font-semibold">2.</span>
                <span>Type the corresponding UFW command in the command input box</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-400 font-semibold">3.</span>
                <span>Click "Check Command" button to verify if your syntax is correct</span>
              </li>
            </ol>
          </div>
        </div>
      </Card>

      {/* Difficulty & Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Difficulty Selector */}
        <Card>
          <h3 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
            <Zap className="w-5 h-5 text-yellow-500" />
            Difficulty Level (Quick Fill)
          </h3>
          <div className="grid grid-cols-3 gap-2">
            {[
              { value: 'easy', label: 'Easy', color: 'green' },
              { value: 'medium', label: 'Medium', color: 'yellow' },
              { value: 'hard', label: 'Hard', color: 'red' }
            ].map((level) => (
              <button
                key={level.value}
                onClick={() => setDifficulty(level.value)}
                className={`px-3 py-2 rounded-lg border-2 transition-all text-sm font-semibold ${
                  difficulty === level.value
                    ? `bg-${level.color}-500/20 border-${level.color}-500 text-${level.color}-400`
                    : 'bg-slate-700/30 border-slate-600 text-slate-300 hover:border-slate-500'
                }`}
              >
                {level.label}
              </button>
            ))}
          </div>
          <p className="text-slate-400 text-xs mt-2">
            {difficulty === 'easy' && 'Basic rules without source or insert'}
            {difficulty === 'medium' && 'Includes optional direction and source'}
            {difficulty === 'hard' && 'Complex rules with insert and subnets'}
          </p>
        </Card>

        {/* Quick Actions */}
        <Card>
          <h3 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-purple-500" />
            Quick Actions
          </h3>
          <div className="flex gap-2">
            <Button
              variant="outline"
              onClick={handleQuickFill}
              className="flex items-center gap-2 flex-1"
            >
              <Sparkles className="w-4 h-4" />
              Quick Fill
            </Button>
            <Button
              variant="outline"
              onClick={() => setShowExamples(!showExamples)}
              className="flex items-center gap-2 flex-1"
            >
              <BookOpen className="w-4 h-4" />
              Examples
            </Button>
          </div>
        </Card>
      </div>

      {/* Examples Modal/Section */}
      {showExamples && (
        <Card className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 border-purple-500/30">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-white flex items-center gap-2">
              <BookOpen className="w-6 h-6 text-purple-500" />
              Example Commands
            </h3>
            <button
              onClick={() => setShowExamples(false)}
              className="text-slate-400 hover:text-white"
            >
              <XCircle className="w-5 h-5" />
            </button>
          </div>
          <div className="space-y-4">
            <div>
              <p className="text-sm font-semibold text-purple-400 mb-2">Basic Format:</p>
              <div className="bg-slate-900 rounded-lg p-3 border border-slate-700">
                <code className="text-green-400 font-mono text-sm">sudo ufw allow 22/tcp</code>
              </div>
            </div>
            <div>
              <p className="text-sm font-semibold text-purple-400 mb-2">With Direction:</p>
              <div className="bg-slate-900 rounded-lg p-3 border border-slate-700">
                <code className="text-green-400 font-mono text-sm">sudo ufw deny in 3306/tcp</code>
              </div>
            </div>
            <div>
              <p className="text-sm font-semibold text-purple-400 mb-2">With Source:</p>
              <div className="bg-slate-900 rounded-lg p-3 border border-slate-700">
                <code className="text-green-400 font-mono text-sm">sudo ufw allow from 192.168.1.100 to any port 80 proto tcp</code>
              </div>
            </div>
            <div>
              <p className="text-sm font-semibold text-purple-400 mb-2">With Source and Direction:</p>
              <div className="bg-slate-900 rounded-lg p-3 border border-slate-700">
                <code className="text-green-400 font-mono text-sm">sudo ufw allow in from 192.168.1.0/24 to any port 443 proto tcp</code>
              </div>
            </div>
            <div>
              <p className="text-sm font-semibold text-purple-400 mb-2">Insert at Position:</p>
              <div className="bg-slate-900 rounded-lg p-3 border border-slate-700">
                <code className="text-green-400 font-mono text-sm">sudo ufw insert 1 deny 22/tcp</code>
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Main Content - Configure Rule with 2-column layout */}
      <Card>
        <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
          <Shield className="w-6 h-6 text-orange-500" />
          Configure Rule
        </h2>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-x-8 gap-y-5">
          {/* LEFT COLUMN */}
          {/* Action */}
          <div>
            <label className="block text-sm font-semibold text-white mb-2">
              Action <span className="text-red-400">*</span>
            </label>
            <div className="grid grid-cols-3 gap-2">
              {['allow', 'deny', 'reject'].map((action) => (
                <button
                  key={action}
                  onClick={() => setConfig({ ...config, action })}
                  className={`px-3 py-2 rounded-lg border-2 transition-all text-sm ${
                    config.action === action
                      ? 'bg-orange-500/20 border-orange-500 text-orange-400 font-semibold'
                      : 'bg-slate-700/30 border-slate-600 text-slate-300 hover:border-slate-500'
                  }`}
                >
                  {action.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* RIGHT COLUMN */}
          {/* Protocol */}
          <div>
            <label className="block text-sm font-semibold text-white mb-2">
              Protocol <span className="text-red-400">*</span>
            </label>
            <div className="grid grid-cols-2 gap-2">
              {['tcp', 'udp'].map((protocol) => (
                <button
                  key={protocol}
                  onClick={() => setConfig({ ...config, protocol })}
                  className={`px-3 py-2 rounded-lg border-2 transition-all text-sm ${
                    config.protocol === protocol
                      ? 'bg-purple-500/20 border-purple-500 text-purple-400 font-semibold'
                      : 'bg-slate-700/30 border-slate-600 text-slate-300 hover:border-slate-500'
                  }`}
                >
                  {protocol.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* LEFT COLUMN */}
          {/* Port */}
          <div>
            <label className="block text-sm font-semibold text-white mb-2">
              Port <span className="text-red-400">*</span>
            </label>
            <Input
              type="text"
              placeholder="22"
              value={config.port}
              onChange={(e) => setConfig({ ...config, port: e.target.value })}
            />
          </div>

          {/* RIGHT COLUMN */}
          {/* Direction */}
          <div>
            <label className="block text-sm font-semibold text-white mb-2">
              Direction <span className="text-slate-400 text-xs">(Optional)</span>
            </label>
            <div className="grid grid-cols-3 gap-2">
              <button
                onClick={() => setConfig({ ...config, direction: '' })}
                className={`px-3 py-2 rounded-lg border-2 transition-all text-sm ${
                  config.direction === ''
                    ? 'bg-slate-500/20 border-slate-400 text-slate-300 font-semibold'
                    : 'bg-slate-700/30 border-slate-600 text-slate-400 hover:border-slate-500'
                }`}
              >
                None
              </button>
              {['in', 'out'].map((dir) => (
                <button
                  key={dir}
                  onClick={() => setConfig({ ...config, direction: dir })}
                  className={`px-3 py-2 rounded-lg border-2 transition-all text-sm ${
                    config.direction === dir
                      ? 'bg-blue-500/20 border-blue-500 text-blue-400 font-semibold'
                      : 'bg-slate-700/30 border-slate-600 text-slate-300 hover:border-slate-500'
                  }`}
                >
                  {dir.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* LEFT COLUMN - Spans full width on mobile, left on desktop */}
          {/* Source */}
          <div className="lg:col-span-1">
            <label className="block text-sm font-semibold text-white mb-2">
              Source <span className="text-slate-400 text-xs">(Optional)</span>
            </label>
            <Input
              type="text"
              placeholder="192.168.1.100 or 2001:db8::1"
              value={config.source}
              onChange={(e) => setConfig({ ...config, source: e.target.value })}
              className={config.source && !validateIPAddress(config.source) ? 'border-red-500' : ''}
            />
            {config.source && !validateIPAddress(config.source) && (
              <p className="text-red-400 text-xs mt-1 flex items-center gap-1">
                <XCircle className="w-3 h-3" />
                Invalid IPv4/IPv6 address or subnet
              </p>
            )}
          </div>

          {/* RIGHT COLUMN */}
          {/* Rule Type */}
          <div className="lg:col-span-1">
            <label className="block text-sm font-semibold text-white mb-2">
              Rule Type <span className="text-red-400">*</span>
            </label>
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => setConfig({ ...config, ruleType: 'normal', ruleNumber: '' })}
                className={`px-3 py-2 rounded-lg border-2 transition-all text-sm ${
                  config.ruleType === 'normal'
                    ? 'bg-green-500/20 border-green-500 text-green-400 font-semibold'
                    : 'bg-slate-700/30 border-slate-600 text-slate-300 hover:border-slate-500'
                }`}
              >
                Normal
              </button>
              <button
                onClick={() => setConfig({ ...config, ruleType: 'insert' })}
                className={`px-3 py-2 rounded-lg border-2 transition-all text-sm ${
                  config.ruleType === 'insert'
                    ? 'bg-orange-500/20 border-orange-500 text-orange-400 font-semibold'
                    : 'bg-slate-700/30 border-slate-600 text-slate-300 hover:border-slate-500'
                }`}
              >
                Insert
              </button>
            </div>

            {config.ruleType === 'insert' && (
              <div className="mt-2">
                <Input
                  type="text"
                  placeholder="Position (e.g., 1)"
                  value={config.ruleNumber}
                  onChange={(e) => setConfig({ ...config, ruleNumber: e.target.value })}
                />
              </div>
            )}
          </div>

          {/* Action Buttons - Full width at bottom */}
          <div className="lg:col-span-2 pt-4 border-t border-slate-700 flex gap-2">
            <Button
              variant="outline"
              onClick={handleReset}
              className="flex items-center gap-2"
              size="sm"
            >
              <RotateCcw className="w-4 h-4" />
              Reset
            </Button>
          </div>
        </div>
      </Card>

      {/* Configuration Summary */}
      <Card className="bg-slate-800/50 border-slate-600">
        <h3 className="text-lg font-semibold text-white mb-3">Current Configuration</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
          <div>
            <span className="text-slate-400 block mb-1">Action:</span>
            <span className="text-orange-400 font-mono font-semibold">{config.action || '-'}</span>
          </div>
          <div>
            <span className="text-slate-400 block mb-1">Port:</span>
            <span className="text-purple-400 font-mono font-semibold">{config.port || '-'}</span>
          </div>
          <div>
            <span className="text-slate-400 block mb-1">Protocol:</span>
            <span className="text-purple-400 font-mono font-semibold">{config.protocol || '-'}</span>
          </div>
          <div>
            <span className="text-slate-400 block mb-1">Direction:</span>
            <span className="text-blue-400 font-mono font-semibold">{config.direction || 'none'}</span>
          </div>
          <div>
            <span className="text-slate-400 block mb-1">Source:</span>
            <span className="text-cyan-400 font-mono text-xs">{config.source || 'any'}</span>
          </div>
          <div>
            <span className="text-slate-400 block mb-1">Type:</span>
            <span className="text-green-400 font-mono font-semibold">
              {config.ruleType === 'insert' ? `insert ${config.ruleNumber || '?'}` : 'normal'}
            </span>
          </div>
        </div>
      </Card>

      {/* Command Input Card */}
      <Card>
        <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
          <Terminal className="w-6 h-6 text-purple-500" />
          Write Command
        </h2>

        {/* Attempts Counter */}
        <div className="mb-4 flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-700">
          <span className="text-slate-400 text-sm">Attempts Remaining:</span>
          <span className={`text-lg font-bold ${
            attemptsLeft > 3 ? 'text-green-400' : 
            attemptsLeft > 1 ? 'text-yellow-400' : 
            'text-red-400'
          }`}>
            {attemptsLeft} / {maxAttempts}
          </span>
        </div>

        <div className="space-y-4">
              {/* Command Input */}
              <div>
                <label className="block text-sm font-semibold text-white mb-2">
                  Your UFW Command:
                </label>
                <div className="bg-slate-900 rounded-lg border-2 border-slate-700 focus-within:border-green-500 transition-colors">
                  <input
                    type="text"
                    value={userCommand}
                    onChange={(e) => setUserCommand(e.target.value)}
                    placeholder="sudo ufw ..."
                    className="w-full bg-transparent text-green-400 font-mono px-4 py-3 outline-none placeholder:text-slate-600"
                    disabled={!isFormValid() || attemptsLeft === 0}
                  />
                </div>
                <p className="text-slate-400 text-xs mt-1 flex items-center gap-1">
                  <Lightbulb className="w-3 h-3" />
                  Start with "sudo ufw"
                </p>
              </div>

              {/* Check & Hint Buttons */}
              <div className="flex gap-3">
                <Button
                  onClick={handleCheckCommand}
                  disabled={!isFormValid() || !userCommand.trim() || attemptsLeft === 0}
                  className="flex items-center gap-2"
                  size="sm"
                >
                  <CheckCircle className="w-4 h-4" />
                  Check Command
                </Button>
                <Button
                  variant="outline"
                  onClick={handleShowHint}
                  disabled={!isFormValid() || attemptsLeft === 0}
                  className="flex items-center gap-2"
                  size="sm"
                >
                  <Lightbulb className="w-4 h-4" />
                  Hint
                </Button>
              </div>
            </div>
        </Card>

        {/* Hint Section */}
        {showHint && isFormValid() && (
          <Card className="bg-gradient-to-r from-yellow-500/10 to-amber-500/10 border-yellow-500/30">
            <div className="flex items-start gap-4">
              <Lightbulb className="w-6 h-6 text-yellow-400 flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-lg font-bold text-yellow-400 mb-2"> Hint #{hintsUsed}</h3>
                <p className="text-slate-300">{generateHint()}</p>
              </div>
            </div>
          </Card>
        )}

      {/* Result Section - Full Width Below */}
      {result && (
        <Card className={`${
          result.correct 
            ? 'bg-gradient-to-r from-green-500/10 to-emerald-500/10 border-green-500/30' 
            : result.showAnswer
            ? 'bg-gradient-to-r from-red-500/10 to-orange-500/10 border-red-500/30'
            : 'bg-gradient-to-r from-red-500/10 to-orange-500/10 border-red-500/30'
        }`}>
          <div className="flex items-start gap-4">
            {result.correct ? (
              <CheckCircle className="w-8 h-8 text-green-400 flex-shrink-0" />
            ) : (
              <XCircle className="w-8 h-8 text-red-400 flex-shrink-0" />
            )}
            <div className="flex-1">
              <h3 className={`text-xl font-bold mb-2 ${
                result.correct ? 'text-green-400' : 'text-red-400'
              }`}>
                {result.correct ? 'Correct!' : 'Incorrect'}
              </h3>
              <p className="text-slate-300 mb-4">{result.message}</p>

              {/* Show answer only if showAnswer is true */}
              {result.showAnswer && (
                <div className="space-y-3">
                  {!result.correct && (
                    <div>
                      <p className="text-sm text-slate-400 mb-1">Your command:</p>
                      <div className="bg-slate-900 rounded-lg p-3 border border-slate-700">
                        <code className="text-red-400 font-mono text-sm">{userCommand}</code>
                      </div>
                    </div>
                  )}
                  <div>
                    <p className="text-sm text-slate-400 mb-1">{result.correct ? 'Your command:' : 'Correct command:'}</p>
                    <div className="bg-slate-900 rounded-lg p-3 border border-green-700">
                      <code className="text-green-400 font-mono text-sm">{result.expectedCommand}</code>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Try Again Button */}
          {(result.correct || result.showAnswer) && (
            <div className="mt-6 pt-6 border-t border-slate-700">
              <Button
                onClick={handleTryAnother}
                variant="outline"
                className="flex items-center gap-2"
              >
                <RotateCcw className="w-4 h-4" />
                Try Another Command
              </Button>
            </div>
          )}
        </Card>
      )}
    </div>
  );
};

export default CLICommandPractice;