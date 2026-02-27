import Navbar from "../components/landing/Navbar";
import Hero from "../components/landing/Hero";
import Stats from "../components/landing/Stats";
import Features from "../components/landing/Features";
import Pipeline from "../components/landing/Pipeline";
import DashboardPreview from "../components/landing/DashboardPreview";
import TechStack from "../components/landing/TechStack";
import CallToAction from "../components/landing/CallToAction";
import Footer from "../components/landing/Footer";

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-deep-dark text-white overflow-x-hidden">
      <Navbar />
      <Hero />
      <Stats />
      <Features />
      <Pipeline />
      <DashboardPreview />
      <TechStack />
      <CallToAction />
      <Footer />
    </div>
  );
}
