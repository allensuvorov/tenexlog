import Image from "next/image";
export default function Home() {
  return (
    <main className="flex flex-col items-center justify-center min-h-screen">
      <h1 className="text-2xl font-bold mb-4">TenexLog</h1>
      <a
        href="/upload"
        className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
      >
        Go to Upload Page
      </a>
    </main>
  );
}