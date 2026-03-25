import { useParams } from "react-router-dom";

export default function EventTypeFindings() {
  const { provider, eventType } = useParams();
  return (
    <div className="p-6">
      <h1 className="text-xl font-semibold mb-2">
        {provider} / {eventType}
      </h1>
      <p className="text-muted-foreground text-sm">
        Event type findings coming soon
      </p>
    </div>
  );
}
