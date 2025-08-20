# 🔐 Generador de Contraseñas Seguras

Un generador de contraseñas criptográficamente seguro desarrollado con tecnologías web modernas, diseñado para crear contraseñas robustas mientras educa sobre mejores prácticas de seguridad digital.

## 🎯 Características Principales

### 🔒 Seguridad Avanzada
- **Generación Criptográfica**: Utiliza Web Crypto API para aleatoriedad verdadera
- **Evaluación de Entropía**: Análisis científico basado en teoría de la información
- **Sin Persistencia**: Las contraseñas no se almacenan ni transmiten
- **Client-Side Only**: Todo el procesamiento ocurre localmente en tu navegador

### 🎛️ Configuración Flexible
- **Longitud Variable**: De 4 a 128 caracteres
- **Tipos de Caracteres**: Mayúsculas, minúsculas, números y símbolos
- **Exclusión de Ambiguos**: Opción para evitar caracteres confusos (0, O, l, I)
- **Generación Automática**: Regeneración instantánea al cambiar configuraciones

### 📊 Análisis de Seguridad en Tiempo Real
- **Medidor Visual**: Indicador gráfico de nivel de seguridad
- **Cálculo de Entropía**: Medición precisa en bits de información
- **Estimación de Descifrado**: Tiempo estimado para romper la contraseña
- **Recomendaciones Inteligentes**: Sugerencias personalizadas para mejorar la seguridad

### 🎨 Experiencia de Usuario Superior
- **Diseño Responsivo**: Optimizado para móviles, tablets y desktop
- **Accesibilidad WCAG**: Soporte completo para lectores de pantalla
- **Atajos de Teclado**: Navegación eficiente sin mouse
- **Feedback Educativo**: Consejos de seguridad contextuales

## 🧠 Conceptos de Seguridad Implementados

### Entropía y Teoría de la Información

La **entropía** es la medida fundamental de la aleatoriedad en una contraseña. Se calcula usando la fórmula:

```
Entropía = L × log₂(N)
```

Donde:
- **L** = Longitud de la contraseña
- **N** = Tamaño del conjunto de caracteres disponibles

#### Niveles de Seguridad por Entropía:
- **0-25 bits**: Muy Débil - Vulnerable a ataques básicos
- **25-50 bits**: Débil - Susceptible a ataques automatizados
- **50-75 bits**: Regular - Resistente a ataques casuales
- **75-100 bits**: Buena - Segura para uso general
- **100-125 bits**: Fuerte - Altamente segura
- **125+ bits**: Excelente - Resistente a ataques masivos

### Factores de Evaluación Avanzada

#### 1. Análisis de Patrones
- **Repeticiones**: Detección de caracteres consecutivos idénticos
- **Secuencias**: Identificación de patrones como "123" o "abc"
- **Penalización**: Reducción de entropía efectiva por predictibilidad

#### 2. Bonificación por Diversidad
- **Tipos de Caracteres**: Cada tipo adicional incrementa la seguridad
- **Distribución**: Análisis de la variedad de caracteres utilizados
- **Resistencia**: Mayor diversidad = mayor resistencia a ataques de diccionario

#### 3. Estimación de Tiempo de Descifrado

Basado en velocidades de ataque realistas:
- **Hardware Personal**: ~1 millón de intentos/segundo
- **Hardware Especializado**: ~1 billón de intentos/segundo  
- **Botnets Masivas**: ~1 trillón de intentos/segundo

## 🏗️ Arquitectura Técnica

### Estructura de Archivos
```
password-generator/
├── index.html          # Estructura semántica y accesible
├── css/
│   └── styles.css      # Estilos con variables CSS y BEM
├── js/
│   └── main.js         # Lógica principal y algoritmos
├── assets/
│   └── (recursos multimedia)
└── README.md           # Documentación completa
```

### Tecnologías Utilizadas

#### Frontend
- **HTML5**: Estructura semántica con elementos accesibles
- **CSS3**: Variables CSS, Grid/Flexbox, animaciones suaves
- **JavaScript ES6+**: Clases, async/await, módulos

#### APIs del Navegador
- **Web Crypto API**: Generación de números aleatorios seguros
- **Clipboard API**: Copia segura al portapapeles
- **Intersection Observer**: Optimizaciones de rendimiento

#### Metodologías
- **BEM**: Nomenclatura CSS consistente y mantenible
- **Mobile First**: Diseño responsivo progresivo
- **Progressive Enhancement**: Funcionalidad base + mejoras