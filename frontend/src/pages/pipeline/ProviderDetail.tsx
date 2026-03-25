import { useParams } from "react-router-dom";

export default function ProviderDetail() {
  const { provider } = useParams();
  return (
    <div className="p-6">
      <h1 className="text-xl font-semibold mb-2">Provider: {provider}</h1>
      <p className="text-muted-foreground text-sm">
        Provider detail view coming soon
      </p>
    </div>
  );
}
