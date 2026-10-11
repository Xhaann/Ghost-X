import Application from "./application";

export default function Home() {
  return (
    <main>
      <h1>Ghost X</h1>
      <Application url={process.env.NEXT_PUBLIC_SOCKET_URL} />
    </main>
  );
}
