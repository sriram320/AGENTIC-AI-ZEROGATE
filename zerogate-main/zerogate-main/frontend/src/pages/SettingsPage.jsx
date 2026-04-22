import { useState, useEffect } from 'react';
import { getAgentModels, updateAgentModel } from '../api';

const AGENT_ROLES = [
    { id: 'orchestrator', name: 'General Orchestrator', desc: 'Fallback model for general routing and generic tasks.' },
    { id: 'cypher', name: 'Cypher Architect', desc: 'Translates natural language to exact Memgraph traversal queries.' },
    { id: 'discovery', name: 'Discovery Agent', desc: 'Augments Semgrep by analyzing code for deeper logic flaws.' },
    { id: 'analyst', name: 'Analyst Agent', desc: 'Triages vulnerability seeds to eradicate false positives.' },
    { id: 'patcher', name: 'Patcher Agent', desc: 'Writes secure, AST-aware source code patches.' },
    { id: 'testgen', name: 'Test-Gen Agent', desc: 'Writes automated pytest regressions for the new patches.' },
    { id: 'summarizer', name: 'Summarizer Agent', desc: 'Compiles the final executive markdown report.' }
];

const PROVIDERS = [
    { id: 'ollama', name: 'Ollama (Local)' },
    { id: 'openai', name: 'OpenAI / Compatible' },
    { id: 'anthropic', name: 'Anthropic' },
    { id: 'google', name: 'Google Vertex / AI Studio' },
    { id: 'local', name: 'VLLM / LM Studio (Local)' }
];

export default function SettingsPage() {
    const [agents, setAgents] = useState({});
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(null);
    const [toast, setToast] = useState(null);

    // Form state for each agent
    const [formData, setFormData] = useState({});

    useEffect(() => {
        loadSettings();
    }, []);

    const loadSettings = async () => {
        try {
            const data = await getAgentModels();
            setAgents(data.agents);
            
            const initialForm = {};
            // Initialize form state
            AGENT_ROLES.forEach(role => {
                const config = data.agents[role.id] || { provider: 'ollama', model: '', has_api_key: false };
                initialForm[role.id] = {
                    provider: config.provider,
                    model: config.model,
                    api_key: '',
                    endpoint: ''
                };
            });
            setFormData(initialForm);
        } catch (err) {
            showToast('Failed to load settings from server.', 'error');
        } finally {
            setLoading(false);
        }
    };

    const showToast = (msg, type = 'success') => {
        setToast({ msg, type });
        setTimeout(() => setToast(null), 3000);
    };

    const handleFieldChange = (roleId, field, value) => {
        setFormData(prev => ({
            ...prev,
            [roleId]: {
                ...prev[roleId],
                [field]: value
            }
        }));
    };

    const handleSave = async (roleId) => {
        setSaving(roleId);
        try {
            const dataToSave = {
                role: roleId,
                provider: formData[roleId].provider,
                model: formData[roleId].model
            };
            
            // Only send api_key if the user explicitly typed one in the box to overwrite
            if (formData[roleId].api_key.trim() !== '') {
                dataToSave.api_key = formData[roleId].api_key.trim();
            }
            if (formData[roleId].endpoint.trim() !== '') {
                dataToSave.endpoint = formData[roleId].endpoint.trim();
            }
            
            await updateAgentModel(dataToSave);
            
            // Clear passwords so it doesn't stay in state
            handleFieldChange(roleId, 'api_key', '');
            
            // Update local badge state
            setAgents(prev => ({
                ...prev,
                [roleId]: {
                    ...prev[roleId],
                    provider: dataToSave.provider,
                    model: dataToSave.model,
                    has_api_key: dataToSave.api_key ? true : (prev[roleId]?.has_api_key || false)
                }
            }));
            
            showToast(`${AGENT_ROLES.find(r => r.id === roleId).name} updated successfully!`);
        } catch (err) {
            showToast(`Failed to update ${roleId}: ${err.message}`, 'error');
        } finally {
            setSaving(null);
        }
    };

    if (loading) {
        return <div className="page"><div className="loading-spinner">Loading AI Configurations...</div></div>;
    }

    return (
        <div className="page settings-page">
            <h1 className="page-title">Agent Roster</h1>
            <p className="page-subtitle">
                Assign specialized Open-Source models and API keys to each independent agent in the LangGraph network.
            </p>

            <div className="agent-grid">
                {AGENT_ROLES.map((role) => {
                    const currentConfig = agents[role.id];
                    const form = formData[role.id];

                    return (
                        <div key={role.id} className="agent-card">
                            <div className="agent-card-header">
                                <h3>{role.name}</h3>
                                {currentConfig?.has_api_key ? (
                                    <span className="badge success">Key Configured</span>
                                ) : (
                                    <span className="badge warning">No API Key</span>
                                )}
                            </div>
                            <p className="agent-desc">{role.desc}</p>
                            
                            <div className="form-group row">
                                <div className="input-group provider-group">
                                    <label>Provider</label>
                                    <select 
                                        value={form?.provider || 'ollama'} 
                                        onChange={(e) => handleFieldChange(role.id, 'provider', e.target.value)}
                                        className="styled-select"
                                    >
                                        {PROVIDERS.map(p => (
                                            <option key={p.id} value={p.id}>{p.name}</option>
                                        ))}
                                    </select>
                                </div>
                                <div className="input-group model-group">
                                    <label>Model String</label>
                                    <input 
                                        type="text" 
                                        placeholder="e.g. meta-llama/Llama-3-70b-chat-hf" 
                                        value={form?.model || ''}
                                        onChange={(e) => handleFieldChange(role.id, 'model', e.target.value)}
                                        className="styled-input"
                                    />
                                </div>
                            </div>
                            
                            <div className="form-group row">
                                <div className="input-group flex-2">
                                    <label>API Key (Leave blank to keep existing)</label>
                                    <input 
                                        type="password" 
                                        placeholder="sk-..." 
                                        value={form?.api_key || ''}
                                        onChange={(e) => handleFieldChange(role.id, 'api_key', e.target.value)}
                                        className="styled-input"
                                    />
                                </div>
                            </div>
                            
                            {(form?.provider === 'openai' || form?.provider === 'local') && (
                                <div className="form-group">
                                    <label>Custom Base URL Endpoint (Optional)</label>
                                    <input 
                                        type="text" 
                                        placeholder="https://api.together.xyz/v1" 
                                        value={form?.endpoint || ''}
                                        onChange={(e) => handleFieldChange(role.id, 'endpoint', e.target.value)}
                                        className="styled-input"
                                    />
                                    <small className="hint">Use this for Together AI, Groq, or Hugging Face Inference endpoints using OpenAI compatibility.</small>
                                </div>
                            )}

                            <div className="agent-card-footer">
                                <button 
                                    className="btn primary" 
                                    onClick={() => handleSave(role.id)}
                                    disabled={saving === role.id}
                                >
                                    {saving === role.id ? 'Reconfiguring...' : 'Save Agent'}
                                </button>
                            </div>
                        </div>
                    );
                })}
            </div>

            {toast && (
                <div className={`toast ${toast.type}`}>
                    {toast.msg}
                </div>
            )}
        </div>
    );
}
