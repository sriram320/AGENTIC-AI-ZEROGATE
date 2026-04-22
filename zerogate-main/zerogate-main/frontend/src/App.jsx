import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import ConnectPage from './pages/ConnectPage';
import ReportPage from './pages/ReportPage';
import DiffPage from './pages/DiffPage';
import SettingsPage from './pages/SettingsPage';
import './index.css';

function Navbar() {
  return (
    <nav className="navbar">
      <NavLink to="/" className="navbar-brand">
        <div>
          <div className="logo">⟁ ZeroGate</div>
          <div className="subtitle">Autonomous Security Graph</div>
        </div>
      </NavLink>
      <div className="navbar-links">
        <NavLink to="/" className={({ isActive }) => isActive ? 'active' : ''} end>
          Secure Repo
        </NavLink>
        <NavLink to="/report" className={({ isActive }) => isActive ? 'active' : ''}>
          Reports
        </NavLink>
        <NavLink to="/settings" className={({ isActive }) => isActive ? 'active' : ''}>
          Agents & Keys
        </NavLink>
      </div>
    </nav>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Navbar />
      <Routes>
        <Route path="/" element={<ConnectPage />} />
        <Route path="/report/:projectId" element={<ReportPage />} />
        <Route path="/diff/:projectId/:findingId" element={<DiffPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
