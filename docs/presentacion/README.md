# Presentación y vídeos de Vigía

- [VIGIA_presentacion.pptx](VIGIA_presentacion.pptx): 16 diapositivas en verde sobre negro con capturas reales de la web, gráficos con datos del dataset y notas del presentador. Se importa en Canva arrastrando el archivo (Subir) y queda editable.
  Empieza por el día a día del analista N1 (diapositiva 2) y cada diapositiva lleva en las notas lo que hay que decir.
- [VIGIA_presentacion.pdf](VIGIA_presentacion.pdf): la misma presentación en PDF.
- [vigia_demo_recorrido.mp4](../videos/vigia_demo_recorrido.mp4) (3 min 8 s): recorrido por la web: Panel, carga de `demo_alertas_comunes.jsonl` en Triaje, expediente, Descartes, Playbooks, Mapa y Chat.
- [vigia_demo_lote_jurado.mp4](../videos/vigia_demo_lote_jurado.mp4) (50 s): análisis del lote de alertas comunes en la mesa de Triaje y apertura de un expediente.

La diapositiva 15 presenta a Sergi Mena, Marc Sánchez, Arnau Paz, Marc Martí y Mark Piazuelo. Si se importa el PowerPoint en Canva, comprobad que use Open Sans. El correo de la diapositiva 8 ilustra el patrón de instrucciones ocultas.

El barrido local produjo 11.061 expedientes, con 8.806 alertas elegibles para autocierre y 281 escaladas. Llegaron fuera de horario 163 de las 281 escaladas (58,0 %) y 3.503 de las 11.061 alertas (31,7 %). La latencia local fue de 115 ms en el percentil 95. En el ensayo independiente del lote oficial, el servidor completó 10 expedientes en 0,9 s, con 3 cierres, 6 escalados y 1 abstención. El contraste remoto queda fuera de esas mediciones. El [épico](../../EPIC.md) recoge los ensayos.
