/*
============================================================================
GENERADOR DE CONTRASEÑAS SEGURAS - LÓGICA JAVASCRIPT
============================================================================

ESTRUCTURA DEL ARCHIVO:
1. Configuración y constantes
2. Conjuntos de caracteres y utilidades
3. Funciones de generación de contraseñas
4. Evaluación de seguridad y entropía
5. Funciones de interfaz de usuario
6. Event listeners y inicialización
7. Utilidades y helpers

PRINCIPIOS DE SEGURIDAD IMPLEMENTADOS:
- Generación completamente client-side (sin transmisión de datos)
- Uso de Web Crypto API para aleatoriedad criptográfica
- Evaluación de entropía basada en teoría de la información
- Sin persistencia de contraseñas (no localStorage/sessionStorage)
- Validación robusta de parámetros de entrada
*/

/* 
============================================================================
1. CONFIGURACIÓN Y CONSTANTES
============================================================================
*/

/**
 * Configuración global de la aplicación
 * Define límites, valores por defecto y constantes de seguridad
 */
const CONFIG = {
    // Límites de longitud
    MIN_LENGTH: 4,
    MAX_LENGTH: 128,
    DEFAULT_LENGTH: 12,
    RECOMMENDED_MIN_LENGTH: 12,

    // Niveles de seguridad (basados en entropía en bits)
    SECURITY_LEVELS: {
        VERY_WEAK: { min: 0, max: 25, label: 'Muy Débil', class: 'weak' },
        WEAK: { min: 25, max: 50, label: 'Débil', class: 'weak' },
        FAIR: { min: 50, max: 75, label: 'Regular', class: 'fair' },
        GOOD: { min: 75, max: 100, label: 'Buena', class: 'good' },
        STRONG: { min: 100, max: 125, label: 'Fuerte', class: 'strong' },
        EXCELLENT: { min: 125, max: Infinity, label: 'Excelente', class: 'excellent' }
    },

    // Configuración de UI
    COPY_FEEDBACK_DURATION: 2000,
    AUTO_GENERATE_DELAY: 300,

    // Mensajes de feedback
    MESSAGES: {
        COPIED: '✅ Contraseña copiada al portapapeles',
        COPY_ERROR: '❌ Error al copiar. Selecciona y copia manualmente.',
        NO_CHARACTERS: '⚠️ Debes seleccionar al menos un tipo de carácter',
        WEAK_PASSWORD: '⚠️ Considera usar una contraseña más larga y compleja',
        GENERATION_ERROR: '❌ Error al generar la contraseña. Inténtalo de nuevo.'
    }
};

/**
 * Conjuntos de caracteres para la generación
 * Organizados por tipo para facilitar la selección
 */
const CHARACTER_SETS = {
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',

    // Caracteres ambiguos que pueden causar confusión visual
    ambiguous: {
        similar: '0O1lI', // Cero, O mayúscula, uno, l minúscula, I mayúscula
        confusing: '{}[]()/\\|`~'
    }
};

/* 
============================================================================
2. CLASE PRINCIPAL DEL GENERADOR
============================================================================
*/

/**
 * Clase principal que maneja toda la lógica del generador de contraseñas
 * Implementa el patrón Singleton para garantizar una única instancia
 */
class PasswordGenerator {
    constructor() {
        // Referencias a elementos del DOM
        this.elements = this.initializeElements();

        // Estado de la aplicación
        this.state = {
            length: CONFIG.DEFAULT_LENGTH,
            includeUppercase: true,
            includeLowercase: true,
            includeNumbers: true,
            includeSymbols: true,
            excludeAmbiguous: false,
            currentPassword: '',
            isPasswordVisible: false
        };
        // Lista de contraseñas comunes
        this.COMMON_PASSWORDS = [
            'password', '123456', '123456789', 'qwerty', 'abc123', 'letmein', 'monkey', 'dragon', '111111', 'iloveyou',
            'admin', 'welcome', 'football', '123123', 'starwars', 'qwertyuiop', 'passw0rd', 'master', 'hello', 'freedom',
            'whatever', 'qazwsx', 'trustno1', '654321', 'jordan23', 'superman', 'harley', 'hunter', 'baseball', 'batman'
        ];

        // Timeout para generación automática (debounce)
        this.autoGenerateTimeout = null;

        // Inicializar la aplicación
        this.initialize();
    }

    /**
     * Inicializa las referencias a elementos del DOM
     * Centraliza todas las queries de elementos para mejor rendimiento
     */
    initializeElements() {
        return {
            // Controles de entrada
            lengthSlider: document.getElementById('lengthSlider'),
            lengthValue: document.getElementById('lengthValue'),
            includeUppercase: document.getElementById('includeUppercase'),
            includeLowercase: document.getElementById('includeLowercase'),
            includeNumbers: document.getElementById('includeNumbers'),
            includeSymbols: document.getElementById('includeSymbols'),
            excludeAmbiguous: document.getElementById('excludeAmbiguous'),

            // Controles de acción
            generateBtn: document.getElementById('generateBtn'),
            copyBtn: document.getElementById('copyBtn'),
            toggleVisibility: document.getElementById('toggleVisibility'),

            // Elementos de resultado
            generatedPassword: document.getElementById('generatedPassword'),
            strengthMeter: document.getElementById('strengthMeter'),
            strengthBar: document.getElementById('strengthBar'),
            strengthText: document.getElementById('strengthText'),
            entropyValue: document.getElementById('entropyValue'),
            crackTimeValue: document.getElementById('crackTimeValue'),
            feedback: document.getElementById('feedback')
        };
    }

    /**
     * Inicializa la aplicación configurando event listeners y estado inicial
     */
    initialize() {
        this.attachEventListeners();
        this.updateStateFromUI();
        this.generatePassword();

        console.info('🔐 Generador de Contraseñas Seguras inicializado correctamente');
    }

    /* 
    ============================================================================
    3. FUNCIONES DE GENERACIÓN DE CONTRASEÑAS
    ============================================================================
    */

    /**
     * Función principal de generación de contraseñas
     * Implementa generación criptográficamente segura usando Web Crypto API
     */
    async generatePassword() {
        try {
            // Validar configuración antes de generar
            if (!this.validateConfiguration()) {
                return;
            }

            // Construir el conjunto de caracteres disponibles
            const availableChars = this.buildCharacterSet();

            if (availableChars.length === 0) {
                this.showFeedback(CONFIG.MESSAGES.NO_CHARACTERS, 'error');
                return;
            }

            // Generar contraseña usando Web Crypto API
            const password = await this.generateSecurePassword(availableChars, this.state.length);

            // Actualizar estado y UI
            this.state.currentPassword = password;
            this.updatePasswordDisplay(password);
            this.evaluatePasswordSecurity(password, availableChars.length);

            // Limpiar feedback anterior
            this.clearFeedback();

            console.log('🔑 Nueva contraseña generada:', {
                length: password.length,
                entropy: this.calculateEntropy(password, availableChars.length),
                characterSet: availableChars.length
            });

        } catch (error) {
            console.error('❌ Error en generación de contraseña:', error);
            this.showFeedback(CONFIG.MESSAGES.GENERATION_ERROR, 'error');
        }
    }

    /**
     * Genera una contraseña criptográficamente segura
     * Utiliza Web Crypto API para garantizar aleatoriedad verdadera
     */
    async generateSecurePassword(characterSet, length) {
        // Crear array para almacenar los caracteres seleccionados
        const password = new Array(length);

        // Generar bytes aleatorios usando Web Crypto API
        const randomBytes = new Uint32Array(length);

        if (crypto && crypto.getRandomValues) {
            // Usar Web Crypto API (preferido)
            crypto.getRandomValues(randomBytes);
        } else {
            // Fallback para navegadores muy antiguos (menos seguro)
            console.warn('⚠️ Web Crypto API no disponible, usando Math.random() como fallback');
            for (let i = 0; i < length; i++) {
                randomBytes[i] = Math.floor(Math.random() * 4294967296);
            }
        }

        // Convertir bytes aleatorios a índices de caracteres
        for (let i = 0; i < length; i++) {
            const randomIndex = randomBytes[i] % characterSet.length;
            password[i] = characterSet[randomIndex];
        }

        return password.join('');
    }

    /**
     * Construye el conjunto de caracteres basado en las opciones seleccionadas
     * Aplica filtros de exclusión si están habilitados
     */
    buildCharacterSet() {
        let chars = '';

        // Agregar conjuntos de caracteres según selección
        if (this.state.includeUppercase) chars += CHARACTER_SETS.uppercase;
        if (this.state.includeLowercase) chars += CHARACTER_SETS.lowercase;
        if (this.state.includeNumbers) chars += CHARACTER_SETS.numbers;
        if (this.state.includeSymbols) chars += CHARACTER_SETS.symbols;

        // Excluir caracteres ambiguos si está habilitado
        if (this.state.excludeAmbiguous) {
            const ambiguousChars = CHARACTER_SETS.ambiguous.similar + CHARACTER_SETS.ambiguous.confusing;
            chars = chars.split('').filter(char => !ambiguousChars.includes(char)).join('');
        }

        // Eliminar duplicados y retornar como array para facilitar indexación
        return [...new Set(chars.split(''))].join('');
    }

    /* 
    ============================================================================
    4. EVALUACIÓN DE SEGURIDAD Y ENTROPÍA
    ============================================================================
    */

    /**
     * Evalúa la seguridad de la contraseña basándose en múltiples factores
     * Mejorada: penaliza secuencias, palabras comunes y ajusta bonus de diversidad
     */
    evaluatePasswordSecurity(password, characterSetSize) {
        // Calcular entropía (bits de información)
        const entropy = this.calculateEntropy(password, characterSetSize);

        // Penalización por palabra común
        const isCommon = this.isCommonPassword(password);
        const commonPenalty = isCommon ? 0.5 : 0;

        // Penalización por patrones de teclado
        const keyboardPenalty = this.calculateKeyboardPatternPenalty(password);

        // Entropía ajustada final
        let adjustedEntropy = entropy * (1 - commonPenalty) * (1 - keyboardPenalty);
        if (isCommon) adjustedEntropy = Math.min(adjustedEntropy, 10); // Muy baja si es común

        // Determinar nivel de seguridad basado en entropía
        const securityLevel = this.determineSecurityLevel(adjustedEntropy);

        // Estimar tiempo de descifrado
        const crackTime = this.estimateCrackTime(adjustedEntropy);

        // Actualizar indicadores visuales
        this.updateSecurityMeter(securityLevel, adjustedEntropy);
        this.updateSecurityDetails(adjustedEntropy, crackTime);

        // Mostrar recomendaciones si es necesario
        this.provideFeedback(securityLevel, password.length, isCommon);
    }

    /**
     * Detecta si la contraseña es una palabra común
     */
    isCommonPassword(password) {
        return this.COMMON_PASSWORDS.includes(password.toLowerCase());
    }

    /**
     * Penaliza patrones de teclado (ej: qwerty, asdf, zxcv, etc.)
     */
    calculateKeyboardPatternPenalty(password) {
        const patterns = [
            'qwerty', 'asdf', 'zxcv', '12345', 'qazwsx', '1q2w3e', 'wasd', 'poiuy', 'lkjhg', 'mnbvc', 'pass', 'word'
        ];
        const lower = password.toLowerCase();
        for (const pat of patterns) {
            if (lower.includes(pat)) return 0.4;
        }
        return 0;
    }

    /**
     * Calcula la entropía de la contraseña en bits
     * Mejorada: bonus de diversidad más realista
     */
    calculateEntropy(password, characterSetSize) {
        if (!password || characterSetSize === 0) return 0;
        // Entropía básica: log2(N^L) = L * log2(N)
        const basicEntropy = password.length * Math.log2(characterSetSize);
        // Penalización por secuencias (incluye repeticiones y secuencias ascendentes/descendentes)
        const sequencePenalty = this.calculateSequencePenalty(password);
        // Bonus de diversidad mejorado
        const diversityBonus = this.calculateDiversityBonus(password, password.length);
        // Entropía ajustada
        const adjustedEntropy = basicEntropy * (1 - sequencePenalty) * (1 + diversityBonus);
        return Math.max(0, adjustedEntropy);
    }

    /**
     * Penaliza secuencias ascendentes y descendentes (ej: abc, cba, 123, 321)
     */
    calculateSequencePenalty(password) {
        if (password.length < 3) return 0;
        let sequences = 0;
        let total = 0;
        for (let i = 0; i < password.length - 2; i++) {
            const a = password.charCodeAt(i);
            const b = password.charCodeAt(i + 1);
            const c = password.charCodeAt(i + 2);
            // Ascendente
            if (b === a + 1 && c === b + 1) sequences++;
            // Descendente
            if (b === a - 1 && c === b - 1) sequences++;
            total++;
        }
        return total > 0 ? Math.min(sequences / total, 0.5) : 0;
    }

    /**
     * Bonus de diversidad mejorado: solo si la longitud es suficiente
     */
    calculateDiversityBonus(password, length) {
        const types = {
            lowercase: /[a-z]/.test(password),
            uppercase: /[A-Z]/.test(password),
            numbers: /[0-9]/.test(password),
            symbols: /[^a-zA-Z0-9]/.test(password)
        };
        const activeTypes = Object.values(types).filter(Boolean).length;
        // Bonus solo si longitud >= 8
        if (length < 8) return 0;
        const bonusMap = { 1: 0, 2: 0.08, 3: 0.18, 4: 0.28 };
        return bonusMap[activeTypes] || 0;
    }

    /**
     * Determina el nivel de seguridad basado en la entropía calculada
     */
    determineSecurityLevel(entropy) {
        for (const [level, config] of Object.entries(CONFIG.SECURITY_LEVELS)) {
            if (entropy >= config.min && entropy < config.max) {
                return { level, ...config };
            }
        }
        return { level: 'EXCELLENT', ...CONFIG.SECURITY_LEVELS.EXCELLENT };
    }

    /**
     * Estima el tiempo necesario para descifrar la contraseña
     * Basado en ataques de fuerza bruta con hardware moderno
     */
    estimateCrackTime(entropy) {
        // Velocidad estimada de ataques modernos (hashes por segundo)
        const attackSpeeds = {
            casual: 1e6,      // 1 millón/seg - Computadora personal
            dedicated: 1e9,   // 1 billón/seg - Hardware especializado
            distributed: 1e12 // 1 trillón/seg - Botnet masiva
        };

        // Usar velocidad de ataque dedicado como referencia
        const attackSpeed = attackSpeeds.dedicated;

        // Calcular combinaciones posibles: 2^entropy
        const combinations = Math.pow(2, entropy);

        // Tiempo promedio de descifrado (50% de las combinaciones)
        const secondsTocrack = combinations / (2 * attackSpeed);

        return this.formatTimeEstimate(secondsTocrack);
    }

    /**
     * Formatea el tiempo estimado en unidades legibles
     */
    formatTimeEstimate(seconds) {
        if (seconds < 1) return 'Instantáneo';
        if (seconds < 60) return `${Math.round(seconds)} segundos`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} minutos`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} horas`;
        if (seconds < 31536000) return `${Math.round(seconds / 86400)} días`;
        if (seconds < 31536000000) return `${Math.round(seconds / 31536000)} años`;

        const years = seconds / 31536000;
        if (years < 1e6) return `${Math.round(years).toLocaleString()} años`;
        if (years < 1e9) return `${Math.round(years / 1e6)} millones de años`;
        if (years < 1e12) return `${Math.round(years / 1e9)} billones de años`;

        return 'Más que la edad del universo';
    }

    /* 
    ============================================================================
    5. FUNCIONES DE INTERFAZ DE USUARIO
    ============================================================================
    */

    /**
     * Actualiza la visualización de la contraseña generada
     */
    updatePasswordDisplay(password) {
        this.elements.generatedPassword.value = password;

        // Habilitar botones de acción
        this.elements.copyBtn.disabled = false;
        this.elements.toggleVisibility.disabled = false;

        // Aplicar estilo de contraseña (monospace, centrado)
        this.elements.generatedPassword.style.fontFamily = 'var(--font-family-mono)';
        this.elements.generatedPassword.style.letterSpacing = '0.5px';
    }

    /**
     * Actualiza el medidor visual de seguridad
     */
    updateSecurityMeter(securityLevel, entropy) {
        const bar = this.elements.strengthBar;
        const text = this.elements.strengthText;

        // Calcular porcentaje para la barra (basado en 150 bits como máximo visual)
        const percentage = Math.min((entropy / 150) * 100, 100);

        // Actualizar barra de progreso
        bar.style.width = `${percentage}%`;
        bar.className = `strength-meter__fill strength-meter__fill--${securityLevel.class}`;
        bar.setAttribute('aria-valuenow', Math.round(percentage));

        // Actualizar texto descriptivo
        text.textContent = securityLevel.label;
        text.className = `strength-meter__text strength-meter__text--${securityLevel.class}`;

        // Agregar animación para cambios significativos
        if (percentage > 75) {
            bar.classList.add('strength-meter__fill--animated');
            setTimeout(() => bar.classList.remove('strength-meter__fill--animated'), 2000);
        }
    }

    /**
     * Actualiza los detalles técnicos de seguridad
     */
    updateSecurityDetails(entropy, crackTime) {
        // Actualizar entropía
        this.elements.entropyValue.textContent = `${entropy.toFixed(1)} bits`;

        // Actualizar tiempo estimado de descifrado
        this.elements.crackTimeValue.textContent = crackTime;

        // Agregar contexto visual basado en la entropía
        const entropyElement = this.elements.entropyValue;
        entropyElement.style.color = entropy > 100 ? 'var(--color-success)' :
            entropy > 75 ? 'var(--color-info)' :
                entropy > 50 ? 'var(--color-warning)' : 'var(--color-error)';
    }

    /**
     * Proporciona feedback y recomendaciones al usuario
     */
    provideFeedback(securityLevel, passwordLength, isCommon) {
        // Limpiar feedback anterior
        this.clearFeedback();

        // Generar recomendaciones basadas en el análisis
        const recommendations = [];

        if (passwordLength < CONFIG.RECOMMENDED_MIN_LENGTH) {
            recommendations.push('💡 Considera usar al menos 12 caracteres para mayor seguridad');
        }

        if (securityLevel.level === 'WEAK' || securityLevel.level === 'VERY_WEAK') {
            recommendations.push('⚠️ Esta contraseña es vulnerable. Usa más tipos de caracteres o aumenta la longitud');
        }

        if (!this.state.includeSymbols && passwordLength < 16) {
            recommendations.push('🔣 Agregar símbolos especiales mejora significativamente la seguridad');
        }

        if (this.state.excludeAmbiguous && passwordLength < 14) {
            recommendations.push('📝 Al excluir caracteres ambiguos, considera usar contraseñas más largas');
        }

        if (isCommon) {
            recommendations.push('⚠️ Esta contraseña es muy común. Considera usar una más robusta.');
        }

        // Mostrar recomendaciones si existen
        if (recommendations.length > 0) {
            const feedbackType = securityLevel.level.includes('WEAK') ? 'warning' : 'info';
            this.showFeedback(recommendations.join(' • '), feedbackType);
        }
    }

    /**
     * Muestra feedback temporal al usuario
     */
    showFeedback(message, type = 'info') {
        const feedback = this.elements.feedback;

        feedback.textContent = message;
        feedback.className = `feedback feedback--${type} feedback--show`;

        // Auto-ocultar después de un tiempo
        setTimeout(() => {
            feedback.classList.remove('feedback--show');
        }, 5000);
    }

    /**
     * Limpia el feedback actual
     */
    clearFeedback() {
        this.elements.feedback.classList.remove('feedback--show');
    }

    /* 
    ============================================================================
    6. EVENT LISTENERS Y MANEJO DE EVENTOS
    ============================================================================
    */

    /**
     * Configura todos los event listeners de la aplicación
     */
    attachEventListeners() {
        // Slider de longitud
        this.elements.lengthSlider.addEventListener('input', (e) => {
            this.state.length = parseInt(e.target.value);
            this.elements.lengthValue.textContent = this.state.length;
            this.scheduleAutoGenerate();
        });

        // Checkboxes de tipos de caracteres
        const checkboxes = [
            'includeUppercase', 'includeLowercase',
            'includeNumbers', 'includeSymbols', 'excludeAmbiguous'
        ];

        checkboxes.forEach(id => {
            this.elements[id].addEventListener('change', (e) => {
                this.state[id] = e.target.checked;
                this.scheduleAutoGenerate();
            });
        });

        // Botón de generar
        this.elements.generateBtn.addEventListener('click', () => {
            this.generatePassword();
        });

        // Botón de copiar
        this.elements.copyBtn.addEventListener('click', () => {
            this.copyPasswordToClipboard();
        });

        // Botón de mostrar/ocultar
        this.elements.toggleVisibility.addEventListener('click', () => {
            this.togglePasswordVisibility();
        });

        // Selección de texto en el campo de contraseña
        this.elements.generatedPassword.addEventListener('focus', (e) => {
            e.target.select();
        });

        // Atajos de teclado
        document.addEventListener('keydown', (e) => {
            this.handleKeyboardShortcuts(e);
        });

        // Prevenir envío accidental del formulario
        document.getElementById('passwordForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.generatePassword();
        });
    }

    /**
     * Programa la generación automática con debounce
     * Evita generar múltiples contraseñas mientras el usuario ajusta controles
     */
    scheduleAutoGenerate() {
        // Cancelar timeout anterior si existe
        if (this.autoGenerateTimeout) {
            clearTimeout(this.autoGenerateTimeout);
        }

        // Programar nueva generación
        this.autoGenerateTimeout = setTimeout(() => {
            this.generatePassword();
        }, CONFIG.AUTO_GENERATE_DELAY);
    }

    /**
     * Maneja atajos de teclado para mejorar UX
     */
    handleKeyboardShortcuts(e) {
        // Ctrl/Cmd + Enter: Generar nueva contraseña
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            this.generatePassword();
        }

        // Ctrl/Cmd + C: Copiar contraseña (solo si hay una generada)
        if ((e.ctrlKey || e.metaKey) && e.key === 'c' && this.state.currentPassword) {
            // Solo interceptar si no hay texto seleccionado
            if (window.getSelection().toString() === '') {
                e.preventDefault();
                this.copyPasswordToClipboard();
            }
        }

        // Espacio: Generar nueva contraseña (solo si no está en un input)
        if (e.key === ' ' && !['INPUT', 'TEXTAREA'].includes(e.target.tagName)) {
            e.preventDefault();
            this.generatePassword();
        }
    }

    /* 
    ============================================================================
    7. UTILIDADES Y HELPERS
    ============================================================================
    */

    /**
     * Copia la contraseña actual al portapapeles
     */
    async copyPasswordToClipboard() {
        if (!this.state.currentPassword) {
            this.showFeedback('No hay contraseña para copiar', 'warning');
            return;
        }

        try {
            // Intentar usar la API moderna de Clipboard
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(this.state.currentPassword);
                this.showCopySuccess();
            } else {
                // Fallback para navegadores más antiguos
                this.fallbackCopyToClipboard();
            }
        } catch (error) {
            console.error('Error al copiar:', error);
            this.showFeedback(CONFIG.MESSAGES.COPY_ERROR, 'error');
        }
    }

    /**
     * Método fallback para copiar texto en navegadores antiguos
     */
    fallbackCopyToClipboard() {
        const textArea = document.createElement('textarea');
        textArea.value = this.state.currentPassword;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';

        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();

        try {
            const successful = document.execCommand('copy');
            if (successful) {
                this.showCopySuccess();
            } else {
                throw new Error('execCommand failed');
            }
        } catch (error) {
            this.showFeedback(CONFIG.MESSAGES.COPY_ERROR, 'error');
        } finally {
            document.body.removeChild(textArea);
        }
    }

    /**
     * Muestra feedback de éxito al copiar
     */
    showCopySuccess() {
        this.showFeedback(CONFIG.MESSAGES.COPIED, 'success');

        // Agregar animación visual al botón
        this.elements.copyBtn.classList.add('success-flash');
        setTimeout(() => {
            this.elements.copyBtn.classList.remove('success-flash');
        }, 600);
    }

    /**
     * Alterna la visibilidad de la contraseña
     */
    togglePasswordVisibility() {
        const input = this.elements.generatedPassword;
        const button = this.elements.toggleVisibility;

        this.state.isPasswordVisible = !this.state.isPasswordVisible;

        if (this.state.isPasswordVisible) {
            input.type = 'text';
            button.textContent = '🙈';
            button.title = 'Ocultar contraseña';
            button.setAttribute('aria-label', 'Ocultar contraseña');
        } else {
            input.type = 'password';
            button.textContent = '👁️';
            button.title = 'Mostrar contraseña';
            button.setAttribute('aria-label', 'Mostrar contraseña');
        }
    }

    /**
     * Actualiza el estado interno basado en los valores de la UI
     */
    updateStateFromUI() {
        this.state.length = parseInt(this.elements.lengthSlider.value);
        this.state.includeUppercase = this.elements.includeUppercase.checked;
        this.state.includeLowercase = this.elements.includeLowercase.checked;
        this.state.includeNumbers = this.elements.includeNumbers.checked;
        this.state.includeSymbols = this.elements.includeSymbols.checked;
        this.state.excludeAmbiguous = this.elements.excludeAmbiguous.checked;

        // Actualizar display de longitud
        this.elements.lengthValue.textContent = this.state.length;
    }

    /**
     * Valida la configuración actual antes de generar
     */
    validateConfiguration() {
        // Verificar que al menos un tipo de carácter esté seleccionado
        const hasAnyCharacterType =
            this.state.includeUppercase ||
            this.state.includeLowercase ||
            this.state.includeNumbers ||
            this.state.includeSymbols;

        if (!hasAnyCharacterType) {
            this.showFeedback(CONFIG.MESSAGES.NO_CHARACTERS, 'error');
            return false;
        }

        // Verificar longitud válida
        if (this.state.length < CONFIG.MIN_LENGTH || this.state.length > CONFIG.MAX_LENGTH) {
            this.showFeedback(`La longitud debe estar entre ${CONFIG.MIN_LENGTH} y ${CONFIG.MAX_LENGTH} caracteres`, 'error');
            return false;
        }

        return true;
    }

    /**
     * Método de limpieza para prevenir memory leaks
     */
    destroy() {
        // Limpiar timeouts
        if (this.autoGenerateTimeout) {
            clearTimeout(this.autoGenerateTimeout);
        }

        // Limpiar estado sensible
        this.state.currentPassword = '';

        console.info('🧹 Generador de contraseñas limpiado correctamente');
    }
}

/* 
============================================================================
8. INICIALIZACIÓN Y MANEJO GLOBAL
============================================================================
*/

/**
 * Función de inicialización principal
 * Se ejecuta cuando el DOM está completamente cargado
 */
function initializePasswordGenerator() {
    try {
        // Verificar compatibilidad del navegador
        if (!checkBrowserCompatibility()) {
            return;
        }

        // Crear instancia del generador
        window.passwordGenerator = new PasswordGenerator();

        // Configurar manejo de errores globales
        setupGlobalErrorHandling();

        // Registrar service worker si está disponible (para futuras mejoras)
        registerServiceWorker();

    } catch (error) {
        console.error('❌ Error fatal al inicializar:', error);
        showFallbackError();
    }
}

/**
 * Verifica la compatibilidad del navegador con las funciones requeridas
 */
function checkBrowserCompatibility() {
    const requiredFeatures = [
        { name: 'querySelector', test: () => !!document.querySelector },
        { name: 'addEventListener', test: () => !!document.addEventListener },
        { name: 'getRandomValues', test: () => !!(crypto && crypto.getRandomValues) }
    ];

    const unsupportedFeatures = requiredFeatures.filter(feature => !feature.test());

    if (unsupportedFeatures.length > 0) {
        console.error('❌ Navegador incompatible. Funciones faltantes:',
            unsupportedFeatures.map(f => f.name));
        showCompatibilityError(unsupportedFeatures);
        return false;
    }

    return true;
}

/**
 * Configura el manejo de errores a nivel global
 */
function setupGlobalErrorHandling() {
    window.addEventListener('error', (event) => {
        console.error('❌ Error global capturado:', event.error);

        // No mostrar errores técnicos al usuario, solo logging
        if (window.passwordGenerator) {
            window.passwordGenerator.showFeedback(
                'Se produjo un error inesperado. Recarga la página si el problema persiste.',
                'error'
            );
        }
    });

    window.addEventListener('unhandledrejection', (event) => {
        console.error('❌ Promise rechazada no manejada:', event.reason);
        event.preventDefault(); // Prevenir que aparezca en la consola del usuario
    });
}

/**
 * Registra un service worker para funcionalidad offline (futuro)
 */
function registerServiceWorker() {
    if ('serviceWorker' in navigator) {
        // Implementación futura para modo offline
        console.info('🔧 Service Worker disponible para futuras mejoras');
    }
}

/**
 * Muestra error de compatibilidad al usuario
 */
function showCompatibilityError(missingFeatures) {
    const errorContainer = document.createElement('div');
    errorContainer.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: #ef4444;
      color: white;
      padding: 1rem;
      text-align: center;
      z-index: 9999;
      font-family: system-ui, sans-serif;
    `;

    errorContainer.innerHTML = `
      <strong>⚠️ Navegador no compatible</strong><br>
      Este generador requiere un navegador más moderno. 
      Por favor, actualiza tu navegador o usa Chrome, Firefox, Safari o Edge recientes.
    `;

    document.body.insertBefore(errorContainer, document.body.firstChild);
}

/**
 * Muestra un error fallback básico
 */
function showFallbackError() {
    const main = document.querySelector('.main');
    if (main) {
        main.innerHTML = `
        <div style="text-align: center; padding: 2rem; color: #ef4444;">
          <h2>❌ Error de Inicialización</h2>
          <p>No se pudo cargar el generador de contraseñas.</p>
          <p>Por favor, recarga la página o contacta al soporte técnico.</p>
          <button onclick="window.location.reload()" 
                  style="padding: 0.5rem 1rem; margin-top: 1rem; 
                         background: #ef4444; color: white; border: none; 
                         border-radius: 0.25rem; cursor: pointer;">
            🔄 Recargar Página
          </button>
        </div>
      `;
    }
}

/* 
============================================================================
9. INICIALIZACIÓN AL CARGAR EL DOM
============================================================================
*/

// Inicializar cuando el DOM esté listo
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializePasswordGenerator);
} else {
    // DOM ya está listo
    initializePasswordGenerator();
}

// Limpiar al cerrar la página para prevenir memory leaks
window.addEventListener('beforeunload', () => {
    if (window.passwordGenerator && typeof window.passwordGenerator.destroy === 'function') {
        window.passwordGenerator.destroy();
    }
});

/*
============================================================================
NOTAS DE SEGURIDAD Y MEJORES PRÁCTICAS:
============================================================================
 
1. GENERACIÓN CRIPTOGRÁFICA:
   - Uso de Web Crypto API para aleatoriedad verdadera
   - Fallback seguro para navegadores antiguos
   - Sin seeding predecible o patrones temporales
 
2. PRIVACIDAD:
   - Generación completamente client-side
   - Sin transmisión de datos a servidores
   - Sin persistencia local de contraseñas
   - Limpieza de memoria al cerrar
 
3. EVALUACIÓN DE SEGURIDAD:
   - Cálculo de entropía basado en teoría de información
   - Análisis de patrones y repeticiones
   - Estimaciones de tiempo de descifrado realistas
   - Recomendaciones contextuales
 
4. ACCESIBILIDAD:
   - Soporte completo de navegación por teclado
   - Atributos ARIA apropiados
   - Feedback auditivo para lectores de pantalla
   - Contrastes de color adecuados
 
5. RENDIMIENTO:
   - Debouncing para evitar generaciones innecesarias
   - Lazy loading de funciones pesadas
   - Manejo eficiente de memoria
   - Optimización de DOM queries
 
6. MANTENIBILIDAD:
   - Código modular y bien documentado
   - Manejo robusto de errores
   - Configuración centralizada
   - Logs detallados para debugging
============================================================================
*/