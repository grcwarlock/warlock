import { useParams } from "react-router-dom";

export default function FindingDetail() {
  const { findingId } = useParams();
  return (
    <div className="p-6">
      <h1 className="text-xl font-semibold mb-2">Finding: {findingId}</h1>
      <p className="text-muted-foreground text-sm">
        Finding detail view coming soon
      </p>
    </div>
  );
}
