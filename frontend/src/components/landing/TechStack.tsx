import { useInView } from "../../hooks/useInView";

const techs = [
  { name: "Python", color: "#3776AB" },
  { name: "FastAPI", color: "#009688" },
  { name: "Redis", color: "#DC382D" },
  { name: "React", color: "#61DAFB" },
  { name: "Docker", color: "#2496ED" },
  { name: "Nmap", color: "#00C853" },
  { name: "Celery", color: "#A9CC54" },
  { name: "PostgreSQL", color: "#336791" },
];

export default function TechStack() {
  const { ref, isInView } = useInView(0.2);

  return (
    <section className="py-24" ref={ref}>
      <div className="mx-auto max-w-7xl px-6 text-center space-y-10">
        <h2 className="text-3xl sm:text-4xl font-bold">
          Built <span className="text-gradient-cyan">With</span>
        </h2>

        <div className="flex flex-wrap justify-center gap-4">
          {techs.map((t, i) => (
            <div
              key={t.name}
              className={`glass rounded-full px-5 py-2.5 flex items-center gap-2.5 hover:border-cyan-accent/30 hover:shadow-[0_0_16px_rgba(0,240,255,0.1)] transition-all duration-300 ${
                isInView ? "animate-fade-in-up" : "opacity-0"
              }`}
              style={{ animationDelay: `${i * 70}ms` }}
            >
              <span
                className="h-2.5 w-2.5 rounded-full"
                style={{ backgroundColor: t.color }}
              />
              <span className="text-sm font-medium text-white">{t.name}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
