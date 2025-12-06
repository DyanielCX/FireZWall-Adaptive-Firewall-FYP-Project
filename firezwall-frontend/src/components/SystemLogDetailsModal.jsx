// ============================================
// System Log Details Modal Component
// Location: /src/components/SystemLogDetailsModal.jsx
// ============================================
import { X, Calendar, AlertCircle, Shield, User, Globe, Server, FileText } from 'lucide-react';
import Card from './ui/Card';
import Button from './ui/Button';

const SystemLogDetailsModal = ({ isOpen, onClose, log }) => {
  if (!isOpen || !log) return null;

  const getLevelBadge = (level) => {
    switch (level?.toUpperCase()) {
      case 'INFO':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'WARNING':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'ERROR':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const getModuleBadge = (module) => {
    switch (module?.toLowerCase()) {
      case 'auth':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
      case 'firewall':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'honeypot':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'syslog':
        return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const handleClose = () => {
    document.body.style.overflow = 'unset';
    onClose();
  };

  // Lock body scroll when modal opens
  document.body.style.overflow = 'hidden';

  return (
    <div 
      className="fixed inset-0 bg-black/70 flex items-start justify-center z-50 p-4 overflow-y-auto"
      onClick={handleClose}
    >
      <div 
        className="w-full max-w-3xl my-8 pt-8"
        onClick={(e) => e.stopPropagation()}
      >
        <Card className="relative">
          {/* Header */}
          <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-700">
            <div className="flex items-center gap-3">
              <div className="bg-orange-500/20 p-2 rounded-lg">
                <FileText className="w-6 h-6 text-orange-500" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-white">System Log Details</h2>
                <p className="text-sm text-slate-400">Log ID: #{log.id}</p>
              </div>
            </div>
            <button
              onClick={handleClose}
              className="text-slate-400 hover:text-white transition-colors p-2 hover:bg-slate-700 rounded-lg"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Content */}
          <div className="space-y-6">
            {/* Basic Information */}
            <div>
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                Basic Information
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-slate-700/30 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                    <Calendar className="w-4 h-4" />
                    <span>Timestamp</span>
                  </div>
                  <p className="text-white font-medium">{log.timestamp}</p>
                </div>

                <div className="bg-slate-700/30 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                    <AlertCircle className="w-4 h-4" />
                    <span>Level</span>
                  </div>
                  <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getLevelBadge(log.level)}`}>
                    {log.level}
                  </span>
                </div>

                <div className="bg-slate-700/30 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                    <Shield className="w-4 h-4" />
                    <span>Module</span>
                  </div>
                  <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getModuleBadge(log.module)}`}>
                    {log.module}
                  </span>
                </div>

                <div className="bg-slate-700/30 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                    <FileText className="w-4 h-4" />
                    <span>Event Type</span>
                  </div>
                  <p className="text-white font-medium">{log.event_type}</p>
                </div>
              </div>
            </div>

            {/* User & Network Information */}
            <div>
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                User & Network Information
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-slate-700/30 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                    <User className="w-4 h-4" />
                    <span>Username</span>
                  </div>
                  <p className="text-white font-medium font-mono">
                    {log.username || <span className="text-slate-500">N/A</span>}
                  </p>
                </div>

                <div className="bg-slate-700/30 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                    <Globe className="w-4 h-4" />
                    <span>IP Address</span>
                  </div>
                  <p className="text-white font-medium font-mono">{log.ip_addr}</p>
                </div>

                <div className="bg-slate-700/30 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                    <Server className="w-4 h-4" />
                    <span>Method</span>
                  </div>
                  <p className="text-white font-medium">{log.method}</p>
                </div>

                <div className="bg-slate-700/30 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                    <Server className="w-4 h-4" />
                    <span>Endpoint</span>
                  </div>
                  <p className="text-white font-medium font-mono">
                    {log.endpoint || <span className="text-slate-500">N/A</span>}
                  </p>
                </div>
              </div>
            </div>

            {/* Message */}
            <div>
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                Message
              </h3>
              <div className="bg-slate-700/30 rounded-lg p-4">
                <p className="text-white leading-relaxed">{log.message}</p>
              </div>
            </div>

            {/* Details (JSON) */}
            {log.details && Object.keys(log.details).length > 0 && (
              <div>
                <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Additional Details
                </h3>
                <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
                  <pre className="text-sm text-slate-300 overflow-x-auto">
                    {JSON.stringify(log.details, null, 2)}
                  </pre>
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-slate-700">
            <Button
              variant="secondary"
              onClick={handleClose}
            >
              Close
            </Button>
          </div>
        </Card>
      </div>
    </div>
  );
};

export default SystemLogDetailsModal;