import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getReport, getDownloadUrl } from '../api';

export default function ReportPage() {
    const { projectId } = useParams();
    const navigate = useNavigate();
    const [report, setReport] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [filter, setFilter] = useState('all');

    useEffect(() => {
        (async () => {
            try {
                const data = await getReport(projectId);
                setReport(data);
            } catch (err) {
                setError(err.message || 'Failed to load report.');
            } finally {
                setLoading(false);
            }
        })();
    }, [projectId]);

    if (loading) {
        return (
            <div className="page">
                <div className="empty-state">
                    <div className="spinner" />
                    <h3 style={{ marginTop: 16 }}>Loading vulnerability report…</h3>
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="page">
                <div className="empty-state">
                    <div className="icon">⚠️</div>
                    <h3>{error}</h3>
                </div>
            </div>
        );
    }

    const filteredFindings = report.findings.filter(
        (f) => filter === 'all' || f.severity === filter
    );

    return (
        <div className="page">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <div>
                    <h1 className="page-title">🛡️ Vulnerability Report</h1>
                    <p className="page-subtitle">
                        Project {projectId} • Scanned {report.scan_timestamp?.split('T')[0]}
                    </p>
                </div>
                <a
                    href={getDownloadUrl(projectId)}
                    className="btn btn-primary"
                    download
                >
                    ⬇ Download Project
                </a>
            </div>

            {/* Summary Cards */}
            <div className="summary-grid">
                <div className="summary-card total">
                    <span className="label">Total</span>
                    <span className="value">{report.summary.total}</span>
                </div>
                <div className="summary-card critical">
                    <span className="label">Critical</span>
                    <span className="value">{report.summary.critical}</span>
                </div>
                <div className="summary-card high">
                    <span className="label">High</span>
                    <span className="value">{report.summary.high}</span>
                </div>
                <div className="summary-card medium">
                    <span className="label">Medium</span>
                    <span className="value">{report.summary.medium}</span>
                </div>
                <div className="summary-card low">
                    <span className="label">Low</span>
                    <span className="value">{report.summary.low}</span>
                </div>
            </div>

            {/* Filter */}
            <div style={{ display: 'flex', gap: 8, marginBottom: 24 }}>
                {['all', 'critical', 'high', 'medium', 'low'].map((s) => (
                    <button
                        key={s}
                        className={`btn btn-sm ${filter === s ? 'btn-primary' : 'btn-secondary'}`}
                        onClick={() => setFilter(s)}
                    >
                        {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
                    </button>
                ))}
            </div>

            {/* Findings Table */}
            {filteredFindings.length === 0 ? (
                <div className="empty-state">
                    <div className="icon">🎉</div>
                    <h3>No findings match this filter</h3>
                </div>
            ) : (
                <table className="findings-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Finding</th>
                            <th>Blast Radius</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filteredFindings.map((f) => (
                            <tr key={f.finding_id}>
                                <td>
                                    <span className={`badge ${f.severity}`}>{f.severity}</span>
                                </td>
                                <td>
                                    <div className="finding-title">{f.title}</div>
                                    <div className="finding-category">{f.category}</div>
                                </td>
                                <td>
                                    <div className="finding-blast">
                                        {f.blast_radius.length} file{f.blast_radius.length !== 1 ? 's' : ''}
                                    </div>
                                </td>
                                <td>
                                    <span className={`badge ${f.status === 'applied' ? 'low' : 'medium'}`}>
                                        {f.status}
                                    </span>
                                </td>
                                <td>
                                    {f.status !== 'applied' ? (
                                        <button
                                            className="btn btn-primary btn-sm"
                                            onClick={() => navigate(`/diff/${projectId}/${f.finding_id}`)}
                                        >
                                            🔧 Fix This
                                        </button>
                                    ) : (
                                        <span style={{ color: 'var(--accent-green)', fontSize: 13 }}>
                                            ✓ Applied
                                        </span>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </div>
    );
}
