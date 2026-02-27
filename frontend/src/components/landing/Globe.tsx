import { useEffect, useRef } from "react";
import * as THREE from "three";

interface Arc {
  line: THREE.Line;
  startDot: THREE.Mesh;
  endDot: THREE.Mesh;
  drawProgress: number;
  lifespan: number;
  age: number;
  maxPoints: number;
}

export default function Globe() {
  const containerRef = useRef<HTMLDivElement>(null);
  const mouseRef = useRef({ x: 0, y: 0 });

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(
      45,
      container.clientWidth / container.clientHeight,
      0.1,
      1000
    );
    camera.position.z = 2.8;

    const renderer = new THREE.WebGLRenderer({
      alpha: true,
      antialias: true,
    });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    const globeGroup = new THREE.Group();
    scene.add(globeGroup);

    // Inner solid sphere
    globeGroup.add(
      new THREE.Mesh(
        new THREE.SphereGeometry(0.97, 48, 48),
        new THREE.MeshBasicMaterial({ color: 0x080816 })
      )
    );

    // Wireframe overlay
    globeGroup.add(
      new THREE.Mesh(
        new THREE.SphereGeometry(1, 40, 40),
        new THREE.MeshBasicMaterial({
          color: 0x1a3a4a,
          wireframe: true,
          transparent: true,
          opacity: 0.12,
        })
      )
    );

    // Atmosphere glow
    globeGroup.add(
      new THREE.Mesh(
        new THREE.SphereGeometry(1.12, 32, 32),
        new THREE.MeshBasicMaterial({
          color: 0x00f0ff,
          transparent: true,
          opacity: 0.04,
          side: THREE.BackSide,
        })
      )
    );

    // Surface dots
    const dotCount = 100;
    const dotGeo = new THREE.BufferGeometry();
    const dotPos = new Float32Array(dotCount * 3);
    const dotCol = new Float32Array(dotCount * 3);
    for (let i = 0; i < dotCount; i++) {
      const phi = Math.acos(2 * Math.random() - 1);
      const theta = Math.random() * Math.PI * 2;
      dotPos[i * 3] = 1.01 * Math.sin(phi) * Math.cos(theta);
      dotPos[i * 3 + 1] = 1.01 * Math.cos(phi);
      dotPos[i * 3 + 2] = 1.01 * Math.sin(phi) * Math.sin(theta);
      dotCol[i * 3] = 0;
      dotCol[i * 3 + 1] = 0.7 + Math.random() * 0.3;
      dotCol[i * 3 + 2] = 0.85 + Math.random() * 0.15;
    }
    dotGeo.setAttribute("position", new THREE.BufferAttribute(dotPos, 3));
    dotGeo.setAttribute("color", new THREE.BufferAttribute(dotCol, 3));
    const dotMat = new THREE.PointsMaterial({
      size: 0.018,
      vertexColors: true,
      transparent: true,
      opacity: 0.8,
      sizeAttenuation: true,
    });
    globeGroup.add(new THREE.Points(dotGeo, dotMat));

    // Background particles
    const pCount = 400;
    const pGeo = new THREE.BufferGeometry();
    const pPos = new Float32Array(pCount * 3);
    for (let i = 0; i < pCount; i++) {
      pPos[i * 3] = (Math.random() - 0.5) * 8;
      pPos[i * 3 + 1] = (Math.random() - 0.5) * 8;
      pPos[i * 3 + 2] = (Math.random() - 0.5) * 8;
    }
    pGeo.setAttribute("position", new THREE.BufferAttribute(pPos, 3));
    scene.add(
      new THREE.Points(
        pGeo,
        new THREE.PointsMaterial({
          size: 0.006,
          color: 0x4466aa,
          transparent: true,
          opacity: 0.4,
          sizeAttenuation: true,
        })
      )
    );

    // Arc helpers
    const dotSphereGeo = new THREE.SphereGeometry(0.015, 8, 8);
    const cyanMat = new THREE.MeshBasicMaterial({
      color: 0x00f0ff,
      transparent: true,
      opacity: 0.9,
    });
    const violetMat = new THREE.MeshBasicMaterial({
      color: 0x7b2fff,
      transparent: true,
      opacity: 0.9,
    });

    function randomSpherePoint(): THREE.Vector3 {
      const phi = Math.acos(2 * Math.random() - 1);
      const theta = Math.random() * Math.PI * 2;
      return new THREE.Vector3(
        Math.sin(phi) * Math.cos(theta),
        Math.cos(phi),
        Math.sin(phi) * Math.sin(theta)
      );
    }

    const arcs: Arc[] = [];

    function createArc() {
      const start = randomSpherePoint();
      const end = randomSpherePoint();
      const mid = start
        .clone()
        .add(end)
        .multiplyScalar(0.5)
        .normalize()
        .multiplyScalar(1 + start.distanceTo(end) * 0.4);

      const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
      const points = curve.getPoints(50);
      const geo = new THREE.BufferGeometry().setFromPoints(points);
      geo.setDrawRange(0, 0);

      const isCyan = Math.random() > 0.4;
      const line = new THREE.Line(
        geo,
        new THREE.LineBasicMaterial({
          color: isCyan ? 0x00f0ff : 0x7b2fff,
          transparent: true,
          opacity: 0.7,
        })
      );
      globeGroup.add(line);

      const mat = isCyan ? cyanMat.clone() : violetMat.clone();
      const startDot = new THREE.Mesh(dotSphereGeo, mat);
      startDot.position.copy(start);
      globeGroup.add(startDot);

      const endDot = new THREE.Mesh(dotSphereGeo, mat.clone());
      endDot.position.copy(end);
      endDot.visible = false;
      globeGroup.add(endDot);

      arcs.push({
        line,
        startDot,
        endDot,
        drawProgress: 0,
        lifespan: 2.5 + Math.random() * 2,
        age: 0,
        maxPoints: points.length,
      });
    }

    for (let i = 0; i < 4; i++) createArc();

    // Events
    const onMouseMove = (e: MouseEvent) => {
      mouseRef.current = {
        x: (e.clientX / window.innerWidth) * 2 - 1,
        y: (e.clientY / window.innerHeight) * 2 - 1,
      };
    };
    window.addEventListener("mousemove", onMouseMove);

    const onResize = () => {
      if (!container) return;
      camera.aspect = container.clientWidth / container.clientHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(container.clientWidth, container.clientHeight);
    };
    window.addEventListener("resize", onResize);

    // Animation loop
    const clock = new THREE.Clock();
    let arcTimer = 0;

    function animate() {
      const delta = clock.getDelta();
      const elapsed = clock.getElapsedTime();

      globeGroup.rotation.y += delta * 0.12;
      globeGroup.rotation.x +=
        (mouseRef.current.y * 0.15 - globeGroup.rotation.x) * 0.02;

      // Spawn arcs
      arcTimer += delta;
      if (arcTimer > 1 && arcs.length < 7) {
        createArc();
        arcTimer = 0;
      }

      // Update arcs
      for (let i = arcs.length - 1; i >= 0; i--) {
        const a = arcs[i];
        a.age += delta;

        if (a.age < a.lifespan * 0.4) {
          a.drawProgress = Math.min(1, a.age / (a.lifespan * 0.3));
          a.line.geometry.setDrawRange(
            0,
            Math.floor(a.drawProgress * a.maxPoints)
          );
          if (a.drawProgress > 0.9) a.endDot.visible = true;
        } else {
          const fade =
            (a.age - a.lifespan * 0.4) / (a.lifespan * 0.6);
          const opacity = 0.7 * (1 - fade);
          (a.line.material as THREE.LineBasicMaterial).opacity = opacity;
          (a.startDot.material as THREE.MeshBasicMaterial).opacity = opacity;
          (a.endDot.material as THREE.MeshBasicMaterial).opacity = opacity;
        }

        // Pulse endpoint dots
        const pulse = 1 + Math.sin(elapsed * 4) * 0.3;
        a.startDot.scale.setScalar(pulse);
        a.endDot.scale.setScalar(pulse);

        if (a.age > a.lifespan) {
          globeGroup.remove(a.line, a.startDot, a.endDot);
          a.line.geometry.dispose();
          (a.line.material as THREE.Material).dispose();
          (a.startDot.material as THREE.Material).dispose();
          (a.endDot.material as THREE.Material).dispose();
          arcs.splice(i, 1);
        }
      }

      dotMat.opacity = 0.6 + Math.sin(elapsed * 2) * 0.2;

      renderer.render(scene, camera);
      frameId = requestAnimationFrame(animate);
    }

    let frameId = requestAnimationFrame(animate);

    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("resize", onResize);
      renderer.dispose();
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      scene.traverse((obj) => {
        if (
          obj instanceof THREE.Mesh ||
          obj instanceof THREE.Line ||
          obj instanceof THREE.Points
        ) {
          obj.geometry.dispose();
          if (Array.isArray(obj.material)) {
            obj.material.forEach((m) => m.dispose());
          } else {
            obj.material.dispose();
          }
        }
      });
    };
  }, []);

  return <div ref={containerRef} className="w-full h-full" />;
}
