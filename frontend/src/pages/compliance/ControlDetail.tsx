import { useParams } from "react-router-dom";

export default function ControlDetail() {
  const { frameworkId, controlId } = useParams();
  return (
    <div className="p-6">
      <h1 className="text-xl font-semibold mb-2">
        {frameworkId} / {controlId}
      </h1>
      <p className="text-muted-foreground text-sm">
        Control detail view coming soon
      </p>
    </div>
  );
}
