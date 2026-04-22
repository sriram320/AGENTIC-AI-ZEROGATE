const API_BASE = 'http://localhost:8000';

export async function uploadProject(file) {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/api/projects/upload`, {
        method: 'POST',
        body: formData,
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}

export async function getProjectStatus(projectId) {
    const res = await fetch(`${API_BASE}/api/projects/${projectId}/status`);
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}

export async function getReport(projectId) {
    const res = await fetch(`${API_BASE}/api/projects/${projectId}/report`);
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}

export async function generateFix(findingId, projectId) {
    const res = await fetch(
        `${API_BASE}/api/findings/${findingId}/fix?project_id=${projectId}`,
        { method: 'POST' }
    );
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}

export async function getDiff(findingId, projectId) {
    const res = await fetch(
        `${API_BASE}/api/findings/${findingId}/diff?project_id=${projectId}`
    );
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}

export async function applyFix(findingId, projectId) {
    const res = await fetch(
        `${API_BASE}/api/findings/${findingId}/apply?project_id=${projectId}`,
        { method: 'POST' }
    );
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}

export function getDownloadUrl(projectId) {
    return `${API_BASE}/api/projects/${projectId}/download`;
}

export function createWebSocket(projectId) {
    return new WebSocket(`ws://localhost:8000/ws/${projectId}`);
}

export async function getAgentModels() {
    const res = await fetch(`${API_BASE}/api/settings/models`);
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}

export async function updateAgentModel(payload) {
    const res = await fetch(`${API_BASE}/api/settings/models`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}
