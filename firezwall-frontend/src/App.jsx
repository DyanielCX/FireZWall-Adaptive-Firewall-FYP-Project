// ============================================
// Main App with Router
// Location: /src/App.jsx
// ============================================
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';

// Pages
import Landing from './pages/Landing';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import APIDocumentation from './pages/APIDocs/APIDocumentation';

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/api-docs" element={<APIDocumentation />} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;