# Caso 6: SGSI ISO/IEC 27001:2022. Prueba de concepto

Trabajo final de Gestión de Proyectos 13007 (Universidad El Bosque, 2026-2).
Equipo Caso #6: Sophia Mateus, Samuel Calero, Andrés Gonzales y Thomas Duarte.

## Contenido
- `poc_siem.py`: prueba de concepto del SIEM (Fase III). Simula 11 fuentes de eventos y 70 ataques sintéticos; calcula el volumen diario (GB/día) y mide la detección y la latencia p95.
- `resultados_poc.json`: resultados de la ejecución.

## Ejecución
Requiere Python 3, sin dependencias externas.

    python3 poc_siem.py
    

La semilla es fija (27001), por lo que los resultados son reproducibles.

## Limitaciones
- Todos los datos son sintéticos. No se usaron datos reales de ninguna entidad.
- La PoC no es un SIEM real: valida el dimensionamiento y la lógica de detección.
