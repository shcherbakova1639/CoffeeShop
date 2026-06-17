const burgerBtn = document.getElementById('burgerBtn');
const navMenu = document.getElementById('navMenu');

// Відкриття/Закриття мобільного меню за кліком на бургер
burgerBtn.addEventListener('click', () => {
    navMenu.classList.toggle('active');
    burgerBtn.classList.toggle('open');
});

// Закриття меню при кліку на будь-яке посилання
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', () => {
        navMenu.classList.remove('active');
        burgerBtn.classList.remove('open');
    });
});

// Проста обробка відправки форми замовлення
document.getElementById('coffeeForm').addEventListener('submit', (e) => {
    e.preventDefault();
    alert('Дякуємо! Бариста вже отримав замовлення і починає його готувати.');
    e.target.reset();
});