import { useState, useRef, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { uploadProject, getProjectStatus, createWebSocket } from '../api';

export default function ConnectPage() {
    const [mode, setMode] = useState('github'); // github or local
    const [repoUrl, setRepoUrl] = useState('');
    const [dragOver, setDragOver] = useState(false);
    const [processing, setProcessing] = useState(false);
    const [progress, setProgress] = useState(null);
    const [error, setError] = useState(null);
    const fileInputRef = useRef(null);
    const navigate = useNavigate();

    const handleConnect = async () => {
        if (mode === 'github') {
            await handleGitHubImport();
        } else {
            fileInputRef.current?.click();
        }
    };

    const handleGitHubImport = async () => {
        if (!repoUrl) {
            setError('Please enter a valid GitHub repository URL.');
            return;
        }

        setProcessing(true);
        setError(null);

        try {
            const response = await fetch('/api/github/import', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: repoUrl }),
            });

            if (!response.ok) throw new Error('Failed to initiate GitHub import.');
            
            const data = await response.json();
            startTracking(data.project_id);
        } catch (err) {
            setError(err.message);
            setProcessing(false);
        }
    };

    const handleFile = useCallback(async (file) => {
        if (!file.name.endsWith('.zip')) {
            setError('Please upload a .zip file.');
            return;
        }

        setProcessing(true);
        setError(null);

        try {
            const data = await uploadProject(file);
            startTracking(data.project_id);
        } catch (err) {
            setError(err.message || 'Upload failed.');
            setProcessing(false);
        }
    }, []);

    const startTracking = (projectId) => {
        setProgress({
            status: 'queued',
            progress: 0,
            projectId,
        });

        const ws = createWebSocket(projectId);
        ws.onmessage = (event) => {
            const msg = JSON.parse(event.data);
            if (msg.type === 'status') {
                setProgress(prev => ({
                    ...prev,
                    status: msg.data.status,
                    progress: msg.data.progress || prev.progress,
                }));
                if (msg.data.status === 'done') {
                    ws.close();
                    setTimeout(() => navigate(`/report/${projectId}`), 1500);
                }
            }
            if (msg.type === 'error') {
                setError(msg.data.message);
                ws.close();
                setProcessing(false);
            }
        };
    };

    const statusLabels = {
        queued: 'Initializing Autonomous Engine…',
        parsing: 'Constructing Security Graph…',
        indexing: 'Mapping Code Relationships…',
        scanning: 'Discovery Agent Scanning…',
        analyzing_fixes: 'Multi-Agent Triage & Patching…',
        done: 'Security Graph Finalized.',
        error: 'Engine Failure.',
    };

    const agents = [
        { id: 'ingest', name: 'Ingestion', status: 'done' },
        { id: 'discovery', name: 'Discovery', status: progress?.progress > 0.4 ? 'done' : progress?.status === 'scanning' ? 'active' : 'pending' },
        { id: 'analyst', name: 'Analyst', status: progress?.progress > 0.8 ? 'done' : progress?.status === 'analyzing_fixes' ? 'active' : 'pending' },
        { id: 'patcher', name: 'Patcher', status: progress?.progress > 0.9 ? 'done' : progress?.status === 'analyzing_fixes' ? 'active' : 'pending' },
        { id: 'testgen', name: 'Verification', status: progress?.status === 'done' ? 'done' : 'pending' },
    ];

    return (
        <div className="page">
            <h1 className="page-title">Secure Your Codebase</h1>
            <p className="page-subtitle">
                Connect your repository to initiate an autonomous security audit. 
                ZeroGate builds a multi-dimensional graph of your code to detect and patch vulnerabilities.
            </p>

            {!progress ? (
                <div className="ingest-card">
                    <div className="tabs">
                        <div 
                            className={`tab ${mode === 'github' ? 'active' : ''}`}
                            onClick={() => setMode('github')}
                        >
                            GitHub Repository
                        </div>
                        <div 
                            className={`tab ${mode === 'local' ? 'active' : ''}`}
                            onClick={() => setMode('local')}
                        >
                            Local Folder (ZIP)
                        </div>
                    </div>

                    <div className="input-container">
                        {mode === 'github' ? (
                            <div className="input-group">
                                <label className="input-label">Repository URL</label>
                                <input 
                                    className="input-field"
                                    type="text"
                                    placeholder="https://github.com/organization/repo"
                                    value={repoUrl}
                                    onChange={(e) => setRepoUrl(e.target.value)}
                                    disabled={processing}
                                />
                            </div>
                        ) : (
                            <div 
                                className={`dropzone ${dragOver ? 'drag-over' : ''}`}
                                onDrop={(e) => {
                                    e.preventDefault();
                                    setDragOver(false);
                                    handleFile(e.dataTransfer.files[0]);
                                }}
                                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                                onDragLeave={() => setDragOver(false)}
                                onClick={() => fileInputRef.current?.click()}
                            >
                                <div className="dropzone-icon">📦</div>
                                <div className="dropzone-text">Drop ZIP Source</div>
                                <div className="dropzone-hint">Max file size 50MB</div>
                                <input 
                                    ref={fileInputRef}
                                    type="file"
                                    accept=".zip"
                                    hidden
                                    onChange={(e) => handleFile(e.target.files[0])}
                                />
                            </div>
                        )}

                        <button 
                            className="btn-primary"
                            onClick={handleConnect}
                            disabled={processing}
                        >
                            {processing ? 'Connecting Engine…' : mode === 'github' ? 'Launch Autonomous Scan' : 'Upload & Scan'}
                        </button>
                    </div>
                </div>
            ) : (
                <div className="status-card">
                    <div className="status-header">
                        <div className="status-info">
                            <label className="input-label">Engine Status</label>
                            <h3>{statusLabels[progress.status] || progress.status}</h3>
                        </div>
                        <div className="status-percentage">
                            {Math.round(progress.progress * 100)}%
                        </div>
                    </div>

                    <div className="progress-track">
                        <div 
                            className="progress-bar" 
                            style={{ width: `${progress.progress * 100}%` }}
                        />
                    </div>

                    <div className="agent-grid">
                        {agents.map(agent => (
                            <div key={agent.id} className={`agent-status-item ${agent.status === 'active' ? 'active' : ''}`}>
                                <span className="agent-name">{agent.name}</span>
                                <div className="agent-indicator">
                                    {agent.status === 'done' ? '✅ Ready' : 
                                     agent.status === 'active' ? <><span className="pulse-dot" /> Running</> : 
                                     '⋯ Waiting'}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {error && (
                <div className="toast error">
                    ⚠️ {error}
                </div>
            )}
        </div>
    );
}
