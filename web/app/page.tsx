import Application from "./application";

export default function Home() {
  return <Application url={process.env.NEXT_PUBLIC_SOCKET_URL} />;
}
