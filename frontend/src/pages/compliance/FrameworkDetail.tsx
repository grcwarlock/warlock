import { useParams } from "react-router-dom";

export default function FrameworkDetail() {
  const { frameworkId } = useParams();
  return (
    <div className="p-6">
      <h1 className="text-xl font-semibold mb-2">Framework: {frameworkId}</h1>
      <p className="text-muted-foreground text-sm">
        Framework detail view coming soon
      </p>
    </div>
  );
}
