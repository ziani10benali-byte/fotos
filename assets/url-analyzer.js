// Analizador de URLs para detección de patrones sospechosos

document.addEventListener('DOMContentLoaded', function() {
    const analyzeBtn = document.getElementById('analyze-btn');
    const urlInput = document.getElementById('url-input');
    const resultsDiv = document.getElementById('results');
    const testButtons = document.querySelectorAll('.test-btn');
    
    // Patrones sospechosos para detectar
    const suspiciousPatterns = {
        highRisk: [
            { pattern: /^poweroff:/i, description: 'Protocolo poweroff:// no estándar' },
            { pattern: /^shutdown:/i, description: 'Protocolo shutdown:// sospechoso' },
            { pattern: /^javascript:/i, description: 'Ejecución de JavaScript en URL' },
            { pattern: /^data:/i, description: 'URI de datos potencialmente malicioso' },
            { pattern: /tel:.*[#*]/i, description: 'Código USSD en enlace tel://' },
            { pattern: /vbscript:/i, description: 'Ejecución de VBScript' }
        ],
        mediumRisk: [
            { pattern: /^facetime:/i, description: 'Protocolo que abre aplicación' },
            { pattern: /^itms-services:/i, description: 'Protocolo de instalación de apps' },
            { pattern: /bit\.ly|tinyurl|goo\.gl/i, description: 'URL acortada (podría ocultar destino)' },
            { pattern: /@/i, description: 'Credenciales en URL' },
            { pattern: /\.(exe|msi|bat|cmd)$/i, description: 'Enlace a archivo ejecutable' }
        ],
        safePatterns: [
            { pattern: /^https:\/\//i, description: 'Conexión segura HTTPS' },
            { pattern: /\.(com|org|edu|gov)$/i, description: 'Dominio legítimo' }
        ]
    };
    
    // Función principal de análisis
    function analyzeURL(url) {
        if (!url.trim()) {
            return {
                risk: 'unknown',
                message: 'Por favor, introduce una URL para analizar',
                details: []
            };
        }
        
        const details = [];
        let riskScore = 0;
        let riskLevel = 'low';
        
        // Analizar patrones de alto riesgo
        suspiciousPatterns.highRisk.forEach(item => {
            if (item.pattern.test(url)) {
                riskScore += 10;
                details.push({
                    type: 'high',
                    message: `⚠️ ALTO RIESGO: ${item.description}`
                });
            }
        });
        
        // Analizar patrones de riesgo medio
        suspiciousPatterns.mediumRisk.forEach(item => {
            if (item.pattern.test(url)) {
                riskScore += 5;
                details.push({
                    type: 'medium',
                    message: `⚠️ RIESGO MEDIO: ${item.description}`
                });
            }
        });
        
        // Analizar patrones seguros
        suspiciousPatterns.safePatterns.forEach(item => {
            if (item.pattern.test(url)) {
                riskScore -= 2;
                details.push({
                    type: 'safe',
                    message: `✓ SEGURO: ${item.description}`
                });
            }
        });
        
        // Determinar nivel de riesgo
        if (riskScore >= 10) {
            riskLevel = 'high';
        } else if (riskScore >= 5) {
            riskLevel = 'medium';
        } else {
            riskLevel = 'low';
        }
        
        return {
            risk: riskLevel,
            score: riskScore,
            details: details,
            url: url
        };
    }
    
    // Función para mostrar resultados
    function displayResults(analysis) {
        let riskColor, riskIcon, riskText;
        
        switch(analysis.risk) {
            case 'high':
                riskColor = '#dc2626';
                riskIcon = 'fa-skull-crossbones';
                riskText = 'ALTO RIESGO';
                break;
            case 'medium':
                riskColor = '#f59e0b';
                riskIcon = 'fa-exclamation-triangle';
                riskText = 'RIESGO MEDIO';
                break;
            default:
                riskColor = '#10b981';
                riskIcon = 'fa-check-circle';
                riskText = 'BAJO RIESGO';
        }
        
        let html = `
            <div class="result-card ${analysis.risk}">
                <h3 style="color: ${riskColor};">
                    <i class="fas ${riskIcon}"></i> Resultado: ${riskText}
                </h3>
                <p><strong>URL analizada:</strong> ${analysis.url}</p>
                <p><strong>Puntuación de riesgo:</strong> ${analysis.score}/100</p>
                
                <div class="details" style="margin-top: 1rem;">
                    <h4>Hallazgos:</h4>
        `;
        
        if (analysis.details.length > 0) {
            html += '<ul style="list-style: none; padding-left: 0;">';
            analysis.details.forEach(detail => {
                const color = detail.type === 'high' ? '#dc2626' : 
                             detail.type === 'medium' ? '#f59e0b' : '#10b981';
                html += `<li style="margin: 5px 0; padding: 5px; border-left: 3px solid ${color}; padding-left: 10px;">
                    ${detail.message}
                </li>`;
            });
            html += '</ul>';
        } else {
            html += '<p>No se encontraron patrones sospechosos.</p>';
        }
        
        // Añadir recomendación
        html += `
                </div>
                
                <div class="recommendation" style="margin-top: 1.5rem; padding: 1rem; background: #f3f4f6; border-radius: 8px;">
                    <h4><i class="fas fa-lightbulb"></i> Recomendación:</h4>
                    <p>${
                        analysis.risk === 'high' ? 
                        '❌ NO hagas clic en este enlace. Podría ser malicioso.' :
                        analysis.risk === 'medium' ?
                        '⚠️ Ten precaución. Verifica la fuente antes de hacer clic.' :
                        '✅ Este enlace parece seguro, pero siempre verifica la fuente.'
                    }</p>
                </div>
            </div>
            
            <div class="educational-note" style="margin-top: 1rem; font-size: 0.9rem; color: #6b7280;">
                <p><i class="fas fa-info-circle"></i> 
                <strong>Nota educativa:</strong> Este análisis detecta patrones sospechosos. 
                En la vida real, los antivirus y navegadores modernos tienen protecciones adicionales.</p>
            </div>
        `;
        
        resultsDiv.innerHTML = html;
    }
    
    // Event listeners
    analyzeBtn.addEventListener('click', function() {
        const url = urlInput.value.trim();
        const analysis = analyzeURL(url);
        displayResults(analysis);
    });
    
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            analyzeBtn.click();
        }
    });
    
    testButtons.forEach(button => {
        button.addEventListener('click', function() {
            const testUrl = this.getAttribute('data-url');
            urlInput.value = testUrl;
            
            // Analizar automáticamente después de 500ms
            setTimeout(() => {
                const analysis = analyzeURL(testUrl);
                displayResults(analysis);
            }, 500);
        });
    });
    
    // Analizar la URL por defecto al cargar
    setTimeout(() => {
        const defaultAnalysis = analyzeURL(urlInput.value);
        displayResults(defaultAnalysis);
    }, 1000);
});
