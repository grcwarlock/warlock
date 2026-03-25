import { useParams } from "react-router-dom";

export default function POAMDetail() {
  const { poamId } = useParams();
  return (
    <div className="p-6">
      <h1 className="text-xl font-semibold mb-2">POA&M: {poamId}</h1>
      <p className="text-muted-foreground text-sm">
        POA&M detail view coming soon
      </p>
    </div>
  );
}
