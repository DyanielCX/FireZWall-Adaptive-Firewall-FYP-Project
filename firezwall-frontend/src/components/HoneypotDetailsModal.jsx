// ============================================
// Honeypot Report Details Modal
// Location: /src/components/HoneypotDetailsModal.jsx
// ============================================
import { X, Server, Calendar, Shield, Globe, User, Lock, Clock, FileText, Terminal } from 'lucide-react';
import Button from './ui/Button';
import Card from './ui/Card';

const HoneypotDetailsModal = ({ isOpen, onClose, report }) => {
  if (!isOpen || !report) return null;

  // Prevent scrolling when modal is open
  if (isOpen) {
    document.body.style.overflow = 'hidden';
  } else {
    document.body.style.overflow = 'unset';
  }

  const getEventTypeBadge = (eventType) => {
    switch (eventType?.toLowerCase()) {
      case 'reconnaissance':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'brute-force attack':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'unauthorized access attempt':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const getProtocolBadge = (protocol) => {
    // Handle null value (not string "null")
    if (protocol === null || protocol === undefined) {
      return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
    
    switch (protocol.toLowerCase()) {
      case 'ssh':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'telnet':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const DetailRow = ({ icon: Icon, label, value, className = '' }) => (
    <div className={`flex items-start gap-3 py-3 border-b border-slate-700/50 ${className}`}>
      <div className="bg-slate-700/50 p-2 rounded-lg flex-shrink-0">
        <Icon className="w-4 h-4 text-slate-400" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm text-slate-400 mb-1">{label}</p>
        <p className="text-white break-all">{value || 'N/A'}</p>
      </div>
    </div>
  );

  const handleClose = () => {
    document.body.style.overflow = 'unset';
    onClose();
  };

  return (
    <div 
      className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4"
      onClick={handleClose}
    >
      <div 
        className="bg-slate-800 rounded-xl border border-slate-700 max-w-3xl w-full max-h-[90vh] overflow-hidden shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-slate-700">
          <div className="flex items-center gap-3">
            <div className="bg-gradient-to-br from-orange-500 to-red-600 p-2 rounded-lg">
              <Server className="w-5 h-5 text-white" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-white">
                Honeypot Report Details
              </h3>
              <p className="text-sm text-slate-400">
                Report ID: #{report.id}
              </p>
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
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-180px)]">
          {/* Event Overview */}
          <div className="mb-6">
            <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">
              Event Overview
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="p-4">
                <div className="flex items-center gap-3 mb-2">
                  <Shield className="w-5 h-5 text-orange-500" />
                  <span className="text-sm text-slate-400">Event Type</span>
                </div>
                <span className={`inline-flex items-center px-3 py-1.5 rounded-full text-sm font-medium border ${getEventTypeBadge(report.event_type)}`}>
                  {report.event_type}
                </span>
              </Card>

              <Card className="p-4">
                <div className="flex items-center gap-3 mb-2">
                  <Server className="w-5 h-5 text-orange-500" />
                  <span className="text-sm text-slate-400">Protocol</span>
                </div>
                <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getProtocolBadge(report.protocol)}`}>
                  {report.protocol ? report.protocol.toUpperCase() : 'N/A'}
                </span>
              </Card>
            </div>
          </div>

          {/* Basic Information */}
          <div className="mb-6">
            <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">
              Basic Information
            </h4>
            <Card>
              <DetailRow 
                icon={Calendar} 
                label="Timestamp" 
                value={report.timestamp} 
              />
              <DetailRow 
                icon={FileText} 
                label="Event ID" 
                value={report.eventid} 
              />
              <DetailRow 
                icon={Globe} 
                label="Source IP Address" 
                value={report.src_ip} 
                className="border-b-0"
              />
            </Card>
          </div>

          {/* Credentials (if available) */}
          {(report.username || report.password) && (
            <div className="mb-6">
              <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
                <Lock className="w-4 h-4 text-red-400" />
                Attempted Credentials
              </h4>
              <Card className="bg-red-500/5 border-red-500/20">
                {report.username && (
                  <DetailRow 
                    icon={User} 
                    label="Username" 
                    value={report.username} 
                  />
                )}
                {report.password && (
                  <DetailRow 
                    icon={Lock} 
                    label="Password" 
                    value={report.password} 
                    className="border-b-0"
                  />
                )}
              </Card>
            </div>
          )}

          {/* Session Information (if available) */}
          {(report.duration || report.tty_code) && (
            <div className="mb-6">
              <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">
                Session Information
              </h4>
              <Card>
                {report.duration && (
                  <DetailRow 
                    icon={Clock} 
                    label="Session Duration" 
                    value={report.duration} 
                  />
                )}
                {report.tty_code && (
                  <DetailRow 
                    icon={Terminal} 
                    label="TTY Code" 
                    value={report.tty_code} 
                    className="border-b-0"
                  />
                )}
              </Card>
            </div>
          )}

          {/* Message/Description */}
          {report.message && (
            <div>
              <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">
                Event Message
              </h4>
              <Card className="bg-slate-700/30">
                <div className="flex items-start gap-3">
                  <FileText className="w-5 h-5 text-slate-400 flex-shrink-0 mt-1" />
                  <p className="text-slate-300 leading-relaxed break-words">
                    {report.message}
                  </p>
                </div>
              </Card>
            </div>
          )}

          {/* Severity Warning */}
          {report.event_type?.toLowerCase() === 'brute-force attack' && (
            <Card className="mt-6 bg-red-500/10 border-red-500/30">
              <div className="flex items-start gap-3">
                <div className="bg-red-500/20 p-2 rounded-lg flex-shrink-0">
                  <Shield className="w-5 h-5 text-red-400" />
                </div>
                <div>
                  <p className="text-red-400 font-semibold mb-1">High Severity Event</p>
                  <p className="text-sm text-slate-300">
                    This brute-force attack attempt indicates potentially malicious activity. 
                    Consider blocking the source IP address and reviewing your security policies.
                  </p>
                </div>
              </div>
            </Card>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 p-6 border-t border-slate-700 bg-slate-800/50">
          <Button
            variant="secondary"
            onClick={handleClose}
          >
            Close
          </Button>
        </div>
      </div>
    </div>
  );
};

export default HoneypotDetailsModal;