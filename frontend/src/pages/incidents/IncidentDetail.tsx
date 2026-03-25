import { useParams } from "react-router-dom";

export default function IncidentDetail() {
  const { incidentId } = useParams();
  return (
    <div className="p-6">
      <h1 className="text-xl font-semibold mb-2">Incident: {incidentId}</h1>
      <p className="text-muted-foreground text-sm">
        Incident detail view coming soon
      </p>
    </div>
  );
}
