
import { useEffect, useState } from "react";
import "./App.css";

const API_URL = "http://localhost:8000";

function App() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [error, setError] = useState("");
  const [rescanningIncident, setRescanningIncident] = useState(null);
  const [rescanResult, setRescanResult] = useState(null);
  const [detailIncident, setDetailIncident] = useState(null);
  const [historyRepositoryPath, setHistoryRepositoryPath] = useState("");
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyResult, setHistoryResult] = useState(null);
  const [activity, setActivity] = useState([]);
  const [activityError, setActivityError] = useState("");

  const getApiError = async (response, fallback) => {
    try {
      const data = await response.json();
      return typeof data.detail === "string" ? data.detail : fallback;
    } catch {
      return fallback;
    }
  };

  const loadIncidents = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await fetch(`${API_URL}/incidents/`);

      if (!response.ok) {
        throw new Error(await getApiError(response, "Failed to load incidents."));
      }

      const data = await response.json();
      setIncidents(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };
const loadRemediation = async (incidentId, currentStatus) => {
  try {
    setSelectedIncident(incidentId);
    setRemediation(null);
    setError("");

    // If the incident is still DETECTED,
    // mark it as INVESTIGATING when remediation is opened.
    if ((currentStatus || "").toUpperCase() === "DETECTED") {
      const statusResponse = await fetch(
        `${API_URL}/incidents/${incidentId}`,
        {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            status: "INVESTIGATING",
          }),
        }
      );

      if (!statusResponse.ok) {
        throw new Error(await getApiError(statusResponse, "Failed to update incident status."));
      }

      // Update the status immediately in the dashboard
      setIncidents((currentIncidents) =>
        currentIncidents.map((incident) =>
          incident.incident_id === incidentId
            ? { ...incident, status: "INVESTIGATING" }
            : incident
        )
      );
    }

    // Now load the remediation guidance
    const response = await fetch(
      `${API_URL}/incidents/${incidentId}/remediation`
    );

    if (!response.ok) {
      throw new Error(await getApiError(response, "Failed to load remediation."));
    }

    const data = await response.json();

    // Make sure the displayed remediation status
    // reflects the updated status.
    if ((currentStatus || "").toUpperCase() === "DETECTED") {
      data.status = "INVESTIGATING";
    }

    setRemediation(data);
    loadActivity();
  } catch (err) {
    setError(err.message);
  }
};
const updateIncidentStatus = async (incidentId, newStatus) => {
  try {
    setError("");

    const response = await fetch(
      `${API_URL}/incidents/${incidentId}`,
      {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          status: newStatus,
        }),
      }
    );

    if (!response.ok) {
      throw new Error(await getApiError(response, "Failed to update incident status."));
    }

    setIncidents((currentIncidents) =>
      currentIncidents.map((incident) =>
        incident.incident_id === incidentId
          ? { ...incident, status: newStatus }
          : incident
      )
    );

    setRemediation((currentRemediation) =>
      currentRemediation
        ? {
            ...currentRemediation,
            status: newStatus,
          }
        : currentRemediation
    );
    loadActivity();
  } catch (err) {
    setError(err.message);
  }
};

const rescanIncident = async (incidentId) => {
  setRescanningIncident(incidentId);
  setRescanResult(null);

  try {
    setError("");

    const response = await fetch(
      `${API_URL}/incidents/${incidentId}/rescan`,
      { method: "POST" }
    );

    let data = {};
    try {
      data = await response.json();
    } catch {
      // Use the fallback message below if the response is not valid JSON.
    }

    if (!response.ok) {
      throw new Error(data.detail || "Failed to rescan incident");
    }

    const resultMessage = data.resolved
      ? data.message || "Secret no longer detected. Incident RESOLVED."
      : `${data.message || "Secret still detected."} Incident remains INVESTIGATING.`;

    setRescanResult({
      incidentId,
      message: resultMessage,
      resolved: data.resolved,
    });

    setIncidents((currentIncidents) =>
      currentIncidents.map((incident) =>
        incident.incident_id === incidentId
          ? { ...incident, status: data.status }
          : incident
      )
    );

    setRemediation((currentRemediation) =>
      currentRemediation?.incident_id === incidentId
        ? { ...currentRemediation, status: data.status }
        : currentRemediation
    );
    loadActivity();
  } catch (err) {
    setError(err.message || "Failed to rescan incident");
  } finally {
    setRescanningIncident((currentIncidentId) =>
      currentIncidentId === incidentId ? null : currentIncidentId
    );
  }
};

const loadActivity = async () => {
  try {
    const response = await fetch(`${API_URL}/incidents/activity/`);
    if (!response.ok) {
      throw new Error("Failed to load security activity.");
    }
    setActivity(await response.json());
    setActivityError("");
  } catch (err) {
    setActivityError(err.message || "Failed to load security activity.");
  }
};

const scanGitHistory = async (event) => {
  event.preventDefault();
  if (!historyRepositoryPath.trim()) {
    setError("Enter a repository path to scan its Git history.");
    return;
  }

  setHistoryLoading(true);
  setHistoryResult(null);
  setError("");
  try {
    const response = await fetch(`${API_URL}/history-scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repository_path: historyRepositoryPath.trim() }),
    });
    let data = {};
    try {
      data = await response.json();
    } catch {
      // The fallback below handles a response without a JSON body.
    }
    if (!response.ok) {
      throw new Error(data.detail || "Git history scan failed.");
    }
    setHistoryResult(data);
    loadActivity();
  } catch (err) {
    setError(err.message || "Git history scan failed.");
  } finally {
    setHistoryLoading(false);
  }
};

  useEffect(() => {
    loadIncidents();
    loadActivity();
  }, []);

  const getSeverityClass = (severity) => {
    switch ((severity || "").toUpperCase()) {
      case "CRITICAL":
        return "critical";
      case "HIGH":
        return "high";
      case "MEDIUM":
        return "medium";
      default:
        return "low";
    }
  };

  const severityCounts = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(
    (severity) => ({
      severity,
      count: incidents.filter(
        (incident) => incident.severity?.toUpperCase() === severity
      ).length,
    })
  );
  const maxSeverityCount = Math.max(
    1,
    ...severityCounts.map((item) => item.count)
  );
  const stats = [
    { label: "Total Incidents", count: incidents.length },
    {
      label: "Critical",
      count: severityCounts.find((item) => item.severity === "CRITICAL").count,
    },
    {
      label: "High",
      count: severityCounts.find((item) => item.severity === "HIGH").count,
    },
    {
      label: "Medium",
      count: severityCounts.find((item) => item.severity === "MEDIUM").count,
    },
    {
      label: "Low",
      count: severityCounts.find((item) => item.severity === "LOW").count,
    },
    {
      label: "Detected",
      count: incidents.filter(
        (incident) => incident.status?.toUpperCase() === "DETECTED"
      ).length,
    },
    {
      label: "Investigating",
      count: incidents.filter(
        (incident) => incident.status?.toUpperCase() === "INVESTIGATING"
      ).length,
    },
    {
      label: "Resolved",
      count: incidents.filter(
        (incident) => incident.status?.toUpperCase() === "RESOLVED"
      ).length,
    },
  ];

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>SecretShield</h1>
          <p>Secret Detection & Security Intelligence</p>
        </div>

        <button onClick={loadIncidents} className="refresh-button">
          Refresh
        </button>
      </header>

      <main className="container">
        <section className="stats">
          {stats.map((stat) => (
            <div className="stat-card" key={stat.label}>
              <span>{stat.label}</span>
              <strong>{stat.count}</strong>
            </div>
          ))}
        </section>

        {error && <div className="error">{error}</div>}

        <section className="overview-grid">
          <div className="panel overview-panel">
            <div className="panel-header">
              <div>
                <h2>Severity Distribution</h2>
                <p>Current incident counts by severity</p>
              </div>
            </div>
            <div className="severity-chart">
              {severityCounts.map((item) => (
                <div className="severity-row" key={item.severity}>
                  <span className={`severity-name ${item.severity.toLowerCase()}`}>
                    {item.severity}
                  </span>
                  <div
                    className="severity-track"
                    role="img"
                    aria-label={`${item.count} ${item.severity.toLowerCase()} incidents`}
                  >
                    <span
                      className={`severity-fill ${item.severity.toLowerCase()}`}
                      style={{ width: `${(item.count / maxSeverityCount) * 100}%` }}
                    />
                  </div>
                  <strong>{item.count}</strong>
                </div>
              ))}
            </div>
          </div>

          <div className="panel overview-panel activity-panel">
            <div className="panel-header">
              <div>
                <h2>Security Activity</h2>
                <p>Recent events from scans and incident actions</p>
              </div>
            </div>
            {activityError ? (
              <p className="activity-empty">{activityError}</p>
            ) : activity.length === 0 ? (
              <p className="activity-empty">No security activity recorded yet.</p>
            ) : (
              <ol className="activity-list">
                {activity.slice(0, 8).map((item) => (
                  <li key={item.id}>
                    <span className={`activity-tag ${item.event_type.toLowerCase()}`}>
                      {item.event_type}
                    </span>
                    <div className="activity-description">
                      <span>{item.message}</span>
                      <time dateTime={item.created_at}>
                        {new Date(item.created_at).toLocaleString()}
                      </time>
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </section>

        <section className="panel history-panel">
          <div className="panel-header">
            <div>
              <h2>Git History Scan</h2>
              <p>Find secrets in previous commits, including removed values</p>
            </div>
          </div>
          <form className="history-form" onSubmit={scanGitHistory}>
            <label htmlFor="history-repository-path">Local repository path</label>
            <div className="history-form-controls">
              <input
                id="history-repository-path"
                value={historyRepositoryPath}
                onChange={(event) => setHistoryRepositoryPath(event.target.value)}
                placeholder="C:\\path\\to\\repository"
                autoComplete="off"
              />
              <button className="history-scan-button" disabled={historyLoading}>
                {historyLoading ? "Scanning history..." : "Scan Git History"}
              </button>
            </div>
          </form>
          {historyLoading && (
            <p className="history-feedback" role="status">Scanning repository history...</p>
          )}
          {historyResult && !historyLoading && (
            <div className="history-results">
              <h3>
                {historyResult.findings_count === 0
                  ? "No historical secrets detected."
                  : `${historyResult.findings_count} historical finding(s)`}
              </h3>
              {historyResult.findings?.map((finding, index) => (
                <article className="history-finding" key={`${finding.fingerprint || finding.commit_hash}-${index}`}>
                  <div>
                    <strong>{finding.secret_type || finding.rule_id}</strong>
                    <span className={`badge ${getSeverityClass(finding.severity)}`}>
                      {finding.severity}
                    </span>
                  </div>
                  <p>{finding.file} · commit {finding.commit_hash || "unknown"}</p>
                  <p>Risk {finding.risk_score} · Policy {finding.policy?.action}</p>
                  <button
                    className="history-detail-button"
                    onClick={() => setDetailIncident({
                      ...finding,
                      repository: historyResult.repository_path,
                      file_path: finding.file,
                      status: "Historical exposure",
                    })}
                  >
                    View details
                  </button>
                </article>
              ))}
            </div>
          )}
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Security Incidents</h2>
              <p>Secrets detected by repository scanning · Detected → Investigating → Resolved</p>
            </div>
          </div>

          {loading ? (
            <div className="empty">Loading incidents...</div>
          ) : incidents.length === 0 ? (
            <div className="empty">
              No security incidents found.
            </div>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Incident ID</th>
                    <th>Secret Type</th>
                    <th>Severity</th>
                    <th>Risk Score</th>
                    <th>Status</th>
                    <th>File</th>
                    <th>Action</th>
                  </tr>
                </thead>

                <tbody>
                  {incidents.map((incident) => (
                    <tr key={incident.incident_id}>
                      <td>
                        <button
                          className="incident-link"
                          onClick={() => setDetailIncident(incident)}
                          aria-label={`View details for ${incident.incident_id}`}
                        >
                          {incident.incident_id}
                        </button>
                      </td>

                      <td>{incident.secret_type}</td>

                      <td>
                        <span
                          className={`badge ${getSeverityClass(
                            incident.severity
                          )}`}
                        >
                          {incident.severity}
                        </span>
                      </td>

                      <td>
                        <strong>{incident.risk_score}</strong>
                      </td>

                      <td>
                        <span className={`status-badge ${incident.status?.toLowerCase()}`}>
                            {incident.status}
                        </span>
                        </td>

                      <td className="file-cell">
                        {incident.file_path}
                      </td>

                      <td className="action-cell">
  <button
    className="action-button"
    onClick={() =>
      loadRemediation(
        incident.incident_id,
        incident.status
      )
    }
  >
    Remediation
  </button>

  {incident.status?.toUpperCase() === "INVESTIGATING" && (
    <>
    <button
      className="rescan-button"
      disabled={rescanningIncident === incident.incident_id}
      onClick={() => rescanIncident(incident.incident_id)}
    >
      {rescanningIncident === incident.incident_id ? "Scanning..." : "Rescan"}
    </button>

    <button
      className="resolve-button"
      onClick={() =>
        updateIncidentStatus(
          incident.incident_id,
          "RESOLVED"
        )
      }
    >
      Resolve
    </button>
    </>
  )}

  {incident.status?.toUpperCase() === "RESOLVED" && (
    <span className="resolved-label">
      Resolved
    </span>
  )}

  {rescanResult?.incidentId === incident.incident_id && (
    <span
      className={`rescan-result ${rescanResult.resolved ? "resolved" : "exposed"}`}
      role="status"
    >
      {rescanResult.message}
    </span>
  )}
</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {remediation && (
          <section className="panel remediation-panel">
            <div className="panel-header">
              <div>
                <h2>Remediation Guidance</h2>
                <p>
                  Incident:{" "}
                  <strong>{remediation.incident_id}</strong>
                </p>
              </div>

              <button
                className="close-button"
                onClick={() => {
                  setRemediation(null);
                  setSelectedIncident(null);
                }}
              >
                Close
              </button>
            </div>

            <div className="remediation-content">
              <div className="remediation-summary">
                <div>
                  <span>Secret Type</span>
                  <strong>{remediation.secret_type}</strong>
                </div>

                <div>
                  <span>Severity</span>
                  <strong>{remediation.severity}</strong>
                </div>

                <div>
                  <span>Status</span>
                  <strong>{remediation.status}</strong>
                </div>
              </div>

              <div className="action-box">
                <h3>Recommended Action</h3>
                <p>{remediation.remediation?.action}</p>
              </div>

              <div>
                <h3>Remediation Steps</h3>

                <ol className="steps">
                  {remediation.remediation?.steps?.map(
                    (step, index) => (
                      <li key={index}>{step}</li>
                    )
                  )}
                </ol>
              </div>
            </div>
          </section>
        )}

        {detailIncident && (
          <div
            className="detail-backdrop"
            onClick={() => setDetailIncident(null)}
          >
            <section
              className="detail-modal"
              role="dialog"
              aria-modal="true"
              aria-labelledby="incident-detail-title"
              onClick={(event) => event.stopPropagation()}
            >
              <div className="detail-modal-header">
                <div>
                  <span className={`source-label ${detailIncident.source === "git-history" ? "historical" : "current"}`}>
                    {detailIncident.source === "git-history" ? "Git History" : "Current File"}
                  </span>
                  <h2 id="incident-detail-title">
                    {detailIncident.incident_id || "Historical finding"}
                  </h2>
                </div>
                <button
                  className="close-button"
                  onClick={() => setDetailIncident(null)}
                  aria-label="Close incident details"
                >
                  Close
                </button>
              </div>

              <dl className="detail-grid">
                <div><dt>Repository</dt><dd>{detailIncident.repository || "—"}</dd></div>
                <div><dt>File</dt><dd>{detailIncident.file_path || detailIncident.file || "—"}</dd></div>
                <div><dt>Secret Type</dt><dd>{detailIncident.secret_type || detailIncident.rule_id || "—"}</dd></div>
                <div><dt>Severity</dt><dd>{detailIncident.severity || "—"}</dd></div>
                <div><dt>Risk Score</dt><dd>{detailIncident.risk_score ?? "—"}</dd></div>
                <div><dt>Status</dt><dd>{detailIncident.status || "Historical finding"}</dd></div>
                <div><dt>Fingerprint</dt><dd className="detail-monospace">{detailIncident.fingerprint || "—"}</dd></div>
                <div><dt>Commit Hash</dt><dd className="detail-monospace">{detailIncident.commit_hash || "—"}</dd></div>
                <div><dt>Created At</dt><dd>{detailIncident.created_at ? new Date(detailIncident.created_at).toLocaleString() : "—"}</dd></div>
                <div><dt>Updated At</dt><dd>{detailIncident.updated_at ? new Date(detailIncident.updated_at).toLocaleString() : "—"}</dd></div>
                {detailIncident.line != null && (
                  <div><dt>Line</dt><dd>{detailIncident.line}</dd></div>
                )}
              </dl>

              <div className="detail-section">
                <h3>Description</h3>
                <p>{detailIncident.description || "No description provided."}</p>
              </div>

              <div className="detail-policy">
                <h3>Policy Decision</h3>
                <p>
                  <strong>{detailIncident.policy?.action || "Unavailable"}</strong>
                  {detailIncident.policy?.reason && ` · ${detailIncident.policy.reason}`}
                </p>
              </div>

              <div className="detail-section">
                <h3>AI Guidance</h3>
                <p>
                  {detailIncident.ai_guidance?.message ||
                    "AI guidance is not configured. Use the deterministic risk, policy, and remediation guidance for this incident."}
                </p>
              </div>
            </section>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
