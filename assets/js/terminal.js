
// Terminal Animation Script
document.addEventListener('DOMContentLoaded', function() {
    const commands = [
        "nikto -h http://localhost:3000 -output nikto_report.txt",
        "python3 advanced_zap_validation.py http://localhost:3000 ./scan-results/",
        "burpsuite --intruder --target=localhost:3000 --wordlist=payloads.txt",
        "Assessment Complete: 608 vulnerabilities identified across 3 tools"
    ];

    let currentCommand = 0;
    let currentChar = 0;
    const typewriter = document.getElementById('typewriter');
    const cursor = typewriter.querySelector('.cursor');

    function typeCommand() {
        if (currentCommand < commands.length) {
            const command = commands[currentCommand];

            if (currentChar < command.length) {
                const textNode = document.createTextNode(command[currentChar]);
                typewriter.insertBefore(textNode, cursor);
                currentChar++;
                setTimeout(typeCommand, 50 + Math.random() * 50);
            } else {
                // Wait, then clear and start next command
                setTimeout(() => {
                    // Clear text but keep cursor
                    while (typewriter.firstChild && typewriter.firstChild !== cursor) {
                        typewriter.removeChild(typewriter.firstChild);
                    }
                    currentChar = 0;
                    currentCommand++;

                    if (currentCommand < commands.length) {
                        setTimeout(typeCommand, 500);
                    } else {
                        // Start over
                        currentCommand = 0;
                        setTimeout(typeCommand, 2000);
                    }
                }, 2000);
            }
        }
    }

    // Start typing animation
    setTimeout(typeCommand, 1000);

    // Update timestamp
    function updateTimestamp() {
        const now = new Date();
        const timestamp = now.toLocaleString('en-US', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });

        const lastUpdated = document.getElementById('last-updated');
        if (lastUpdated) {
            lastUpdated.textContent = timestamp;
        }
    }

    updateTimestamp();
    setInterval(updateTimestamp, 1000);

    // Add click handlers for cards
    document.querySelectorAll('.assessment-card').forEach(card => {
        card.addEventListener('click', function(e) {
            // Don't trigger if clicking on action buttons
            if (!e.target.closest('.action-btn')) {
                const cardTitle = this.querySelector('.card-title').textContent;
                console.log(`Clicked on ${cardTitle} card`);
            }
        });
    });
});