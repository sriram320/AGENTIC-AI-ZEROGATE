import { useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { uploadProject, getProjectStatus, createWebSocket } from '../api';

export default function UploadPage() {
    const [dragOver, setDragOver] = useState(false);
    const [uploading, setUploading] = useState(false);
    const [progress, setProgress] = useState(null);
    const [error, setError] = useState(null);
    const fileInputRef = useRef(null);
    const navigate = useNavigate();

    const handleFile = useCallback(async (file) => {
        if (!file.name.endsWith('.zip')) {
            setError('Please upload a .zip file containing your project.');
            return;
        }

        setUploading(true);
        setError(null);

        try {
            const data = await uploadProject(file);
            const projectId = data.project_id;

            setProgress({
                status: 'queued',
                progress: 0,
                projectId,
            });

            // Connect WebSocket for live updates
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
                        setTimeout(() => navigate(`/report/${projectId}`), 1000);
                    }
                }
                if (msg.type === 'error') {
                    setError(msg.data.message);
                    ws.close();
                }
            };

            // Fallback polling in case WS doesn't connect
            ws.onerror = () => {
                pollStatus(projectId);
            };

        } catch (err) {
            setError(err.message || 'Upload failed.');
            setUploading(false);
        }
    }, [navigate]);

    const pollStatus = async (projectId) => {
        const interval = setInterval(async () => {
            try {
                const status = await getProjectStatus(projectId);
                setProgress({
                    status: status.status,
                    progress: status.progress,
                    projectId,
                });
                if (status.status === 'done') {
                    clearInterval(interval);
                    setTimeout(() => navigate(`/report/${projectId}`), 1000);
                }
                if (status.status === 'error') {
                    clearInterval(interval);
                    setError(status.error_message || 'Processing failed.');
                }
            } catch {
                // Keep polling
            }
        }, 2000);
    };

    const handleDrop = (e) => {
        e.preventDefault();
        setDragOver(false);
        const file = e.dataTransfer.files[0];
        if (file) handleFile(file);
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        setDragOver(true);
    };

    const statusLabels = {
        queued: 'Queued…',
        parsing: '🔍 Parsing source code with Tree-sitter…',
        indexing: '📊 Building knowledge graph in Memgraph…',
        scanning: '🛡️ Running Auto-Hunter vulnerability scan…',
        analyzing_fixes: '🤖 LangGraph Multi-Agent Triage & Patch Generation…',
        done: '✅ Scan complete! Redirecting to report…',
        error: '❌ An error occurred.',
    };

    return (
        <div className="page">
            <h1 className="page-title">Analyze a Codebase</h1>
            <p className="page-subtitle">
                Upload a ZIP file of your project to build its security knowledge graph
                and automatically detect vulnerabilities.
            </p>

            {!progress ? (
                <>
                    <div
                        className={`dropzone ${dragOver ? 'drag-over' : ''}`}
                        onDrop={handleDrop}
                        onDragOver={handleDragOver}
                        onDragLeave={() => setDragOver(false)}
                        onClick={() => fileInputRef.current?.click()}
                    >
                        <div className="dropzone-icon">📁</div>
                        <div className="dropzone-text">
                            {uploading ? 'Uploading…' : 'Drop your project ZIP here'}
                        </div>
                        <div className="dropzone-hint">
                            or click to browse • .zip files only
                        </div>
                        <input
                            ref={fileInputRef}
                            type="file"
                            accept=".zip"
                            hidden
                            onChange={(e) => {
                                const file = e.target.files[0];
                                if (file) handleFile(file);
                            }}
                        />
                    </div>
                </>
            ) : (
                <div className="progress-container">
                    <div className="progress-header">
                        <span className="progress-label">
                            {statusLabels[progress.status] || progress.status}
                        </span>
                        <span className="progress-value">
                            {Math.round(progress.progress * 100)}%
                        </span>
                    </div>
                    <div className="progress-bar">
                        <div
                            className="progress-fill"
                            style={{ width: `${progress.progress * 100}%` }}
                        />
                    </div>
                    <div className="progress-status">
                        {progress.status !== 'done' && progress.status !== 'error' && (
                            <>
                                <span className="dot" />
                                Processing project…
                            </>
                        )}
                    </div>
                </div>
            )}

            {error && (
                <div className="toast error" style={{ position: 'relative', marginTop: 16 }}>
                    {error}
                </div>
            )}
        </div>
    );
}
