import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { generateFix, applyFix } from '../api';

export default function DiffPage() {
    const { projectId, findingId } = useParams();
    const navigate = useNavigate();
    const [proposal, setProposal] = useState(null);
    const [loading, setLoading] = useState(true);
    const [applying, setApplying] = useState(false);
    const [applied, setApplied] = useState(false);
    const [error, setError] = useState(null);

    useEffect(() => {
        (async () => {
            try {
                const data = await generateFix(findingId, projectId);
                setProposal(data);
            } catch (err) {
                setError(err.message || 'Failed to generate fix.');
            } finally {
                setLoading(false);
            }
        })();
    }, [findingId, projectId]);

    const handleApply = async () => {
        setApplying(true);
        try {
            const result = await applyFix(findingId, projectId);
            if (result.status === 'applied') {
                setApplied(true);
            } else {
                setError(result.message);
            }
        } catch (err) {
            setError(err.message || 'Failed to apply fix.');
        } finally {
            setApplying(false);
        }
    };

    const renderDiffLines = (diff) => {
        if (!diff) return null;
        return diff.split('\n').map((line, i) => {
            let className = '';
            if (line.startsWith('+') && !line.startsWith('+++')) {
                className = 'diff-line-add';
            } else if (line.startsWith('-') && !line.startsWith('---')) {
                className = 'diff-line-remove';
            }
            return (
                <div key={i} className={className} style={{ padding: '0 24px' }}>
                    {line}
                </div>
            );
        });
    };

    if (loading) {
        return (
            <div className="page">
                <div className="empty-state">
                    <div className="spinner" />
                    <h3 style={{ marginTop: 16 }}>Generating AI-powered fix…</h3>
                    <p style={{ color: 'var(--text-muted)', marginTop: 8 }}>
                        The LLM is analyzing the vulnerability and producing a secure patch.
                    </p>
                </div>
            </div>
        );
    }

    if (error && !proposal) {
        return (
            <div className="page">
                <div className="empty-state">
                    <div className="icon">⚠️</div>
                    <h3>{error}</h3>
                    <button
                        className="btn btn-secondary"
                        style={{ marginTop: 16 }}
                        onClick={() => navigate(`/report/${projectId}`)}
                    >
                        ← Back to Report
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="page">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <div>
                    <h1 className="page-title">🔧 Review Fix</h1>
                    <p className="page-subtitle">
                        Finding: {findingId}
                    </p>
                </div>
                <button
                    className="btn btn-secondary"
                    onClick={() => navigate(`/report/${projectId}`)}
                >
                    ← Back to Report
                </button>
            </div>

            {/* Explanation */}
            {proposal?.explanation && (
                <div className="explanation">
                    <h4>🤖 AI Explanation</h4>
                    <p>{proposal.explanation}</p>
                </div>
            )}

            {/* Diff Viewer */}
            <div className="diff-container">
                <div className="diff-header">
                    <span className="diff-filename">
                        📄 {proposal?.file_path || 'Unknown file'}
                    </span>
                    <div className="diff-actions">
                        {!applied ? (
                            <>
                                <button
                                    className="btn btn-danger btn-sm"
                                    onClick={() => navigate(`/report/${projectId}`)}
                                >
                                    ✕ Reject
                                </button>
                                <button
                                    className="btn btn-primary btn-sm"
                                    onClick={handleApply}
                                    disabled={applying}
                                >
                                    {applying ? (
                                        <>
                                            <span className="spinner" style={{ width: 14, height: 14 }} />
                                            Applying…
                                        </>
                                    ) : (
                                        '✓ Confirm & Apply'
                                    )}
                                </button>
                            </>
                        ) : (
                            <span style={{ color: 'var(--accent-green)', fontWeight: 600 }}>
                                ✅ Fix Applied Successfully
                            </span>
                        )}
                    </div>
                </div>
                <div className="diff-content">
                    <pre style={{ margin: 0 }}>
                        {renderDiffLines(proposal?.unified_diff)}
                    </pre>
                </div>
            </div>

            {applied && (
                <div className="toast success" style={{ position: 'relative', marginTop: 16 }}>
                    Fix has been applied to the source file. Go back to the report to
                    continue reviewing other findings or download the patched project.
                </div>
            )}

            {error && !applied && (
                <div className="toast error" style={{ position: 'relative', marginTop: 16 }}>
                    {error}
                </div>
            )}
        </div>
    );
}
