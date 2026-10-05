import Status from "./status";

export default function Home() {
  return (
    <main>
      <h1>Ghost X</h1>
      <Status url={process.env.NEXT_PUBLIC_SOCKET_URL} />
    </main>
  );
}
